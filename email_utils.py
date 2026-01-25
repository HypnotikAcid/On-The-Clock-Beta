# Email utility for On the Clock Discord Bot
# Based on Replit Mail integration (blueprint:replitmail)
# Implements a reliable outbox pattern with retry/backoff

import os
import json
import base64
import asyncio
import aiohttp
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from logging.handlers import RotatingFileHandler
from typing import List, Dict, Optional, Union, Any
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database connection for email outbox
@contextmanager
def _get_db():
    """Get database connection for email operations"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise Exception("DATABASE_URL not configured")
    
    conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# Persistent email log file - survives workflow restarts
EMAIL_LOG_DIR = Path("data/email_logs")
EMAIL_LOG_FILE = EMAIL_LOG_DIR / "email_audit.log"

def _setup_email_file_logger():
    """Setup a file logger that persists email records to disk"""
    EMAIL_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    email_logger = logging.getLogger("email_audit")
    email_logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if not email_logger.handlers:
        handler = RotatingFileHandler(
            EMAIL_LOG_FILE,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=14  # Keep 2 weeks of logs
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        email_logger.addHandler(handler)
    
    return email_logger

email_file_logger = _setup_email_file_logger()

def log_email_to_file(event_type: str, recipients: list, subject: str, context: dict | None = None, success: bool = True, error: str | None = None):
    """Write email event to persistent log file"""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "recipients": recipients,
        "subject": subject,
        "success": success,
        "context": context or {},
    }
    if error:
        log_entry["error"] = error
    
    email_file_logger.info(json.dumps(log_entry))

class ReplitMailSender:
    """Email utility using Replit's OpenInt mail service"""
    
    def __init__(self):
        self.api_endpoint = "https://connectors.replit.com/api/v2/mailer/send"
        self.auth_token = self._get_auth_token()
    
    def _get_auth_token(self) -> str:
        """Get authentication token from environment variables"""
        # Check for REPL_IDENTITY first (repl environment)
        repl_identity = os.getenv('REPL_IDENTITY')
        if repl_identity:
            return f"repl {repl_identity}"
        
        # Check for WEB_REPL_RENEWAL (deployed environment)
        web_repl_renewal = os.getenv('WEB_REPL_RENEWAL')
        if web_repl_renewal:
            return f"depl {web_repl_renewal}"
        
        raise ValueError(
            "No authentication token found. Please set REPL_IDENTITY or ensure you're running in Replit environment."
        )
    
    async def send_email(
        self,
        to: Union[str, List[str]],
        subject: str,
        text: Optional[str] = None,
        html: Optional[str] = None,
        cc: Optional[Union[str, List[str]]] = None,
        attachments: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Send email using Replit's mail service
        
        Args:
            to: Recipient email address(es)
            subject: Email subject
            text: Plain text body (optional)
            html: HTML body (optional)  
            cc: CC recipient email address(es) (optional)
            attachments: List of attachments (optional)
                Each attachment should be a dict with:
                - filename: str
                - content: str (base64 encoded)
                - contentType: str (optional)
                - encoding: str (default: "base64")
        
        Returns:
            Dict with response from mail service
        """
        
        # Validate inputs
        if not to:
            raise ValueError("Recipient email address is required")
        if not subject:
            raise ValueError("Email subject is required")
        if not text and not html:
            raise ValueError("Either text or html body is required")
        
        # Prepare payload
        payload: dict[str, Any] = {
            "to": to,
            "subject": subject
        }

        if text:
            payload["text"] = text
        if html:
            payload["html"] = html
        if cc:
            payload["cc"] = cc
        if attachments:
            payload["attachments"] = attachments
        
        # Normalize recipient list
        recipient_list = to if isinstance(to, list) else [to]
        cc_list = (cc if isinstance(cc, list) else [cc]) if cc else []
        
        # Console logging
        logger.info(f"📧 EMAIL SEND REQUEST: {subject} -> {recipient_list}")
        
        headers = {
            "Content-Type": "application/json",
            "X_REPLIT_TOKEN": self.auth_token
        }

        # Set 10 second timeout to prevent indefinite hangs
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(
                    self.api_endpoint,
                    headers=headers,
                    json=payload
                ) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        try:
                            error_data = json.loads(error_text)
                            error_message = error_data.get('message', 'Failed to send email')
                        except:
                            error_message = f"HTTP {response.status}: {error_text}"
                        
                        # Log failure to persistent file
                        log_email_to_file(
                            event_type="send_failed",
                            recipients=recipient_list + cc_list,
                            subject=subject,
                            success=False,
                            error=error_message
                        )
                        raise Exception(f"Email send failed: {error_message}")
                    
                    result = await response.json()
                    
                    # Log success to persistent file
                    log_email_to_file(
                        event_type="send_success",
                        recipients=recipient_list + cc_list,
                        subject=subject,
                        success=True
                    )
                    logger.info(f"   EMAIL SENT SUCCESSFULLY to: {recipient_list}")
                    return result
                    
            except aiohttp.ClientError as e:
                # Log network error to persistent file
                log_email_to_file(
                    event_type="network_error",
                    recipients=recipient_list + cc_list,
                    subject=subject,
                    success=False,
                    error=str(e)
                )
                raise Exception(f"Network error sending email: {str(e)}")

    async def send_timeclock_report(
        self,
        to: Union[str, List[str]],
        guild_name: str,
        csv_content: str,
        report_period: str
    ) -> Dict:
        """
        Send timeclock report with CSV attachment
        
        Args:
            to: Recipient email address(es)
            guild_name: Name of the Discord server
            csv_content: CSV report content as string
            report_period: Description of the report period
        
        Returns:
            Dict with response from mail service
        """
        
        # Encode CSV content to base64
        csv_base64 = base64.b64encode(csv_content.encode('utf-8')).decode('utf-8')
        
        # Generate filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"timeclock_report_{guild_name}_{timestamp}.csv"
        
        # Prepare email content
        subject = f"Timeclock Report - {guild_name} ({report_period})"
        
        text_content = f"""
Timeclock Report for {guild_name}

Report Period: {report_period}
Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}

Please find the attached CSV file containing the timeclock data.

---
On the Clock Discord Bot
        """.strip()
        
        html_content = f"""
<html>
<body>
    <h2>Timeclock Report for {guild_name}</h2>
    
    <p><strong>Report Period:</strong> {report_period}</p>
    <p><strong>Generated:</strong> {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <p>Please find the attached CSV file containing the timeclock data.</p>
    
    <hr>
    <p><em>On the Clock Discord Bot</em></p>
</body>
</html>
        """.strip()
        
        # Prepare attachment
        attachments = [{
            "filename": filename,
            "content": csv_base64,
            "contentType": "text/csv",
            "encoding": "base64"
        }]
        
        return await self.send_email(
            to=to,
            subject=subject,
            text=text_content,
            html=html_content,
            attachments=attachments
        )

# Global email sender instance
email_sender = ReplitMailSender()

# ============================================
# EMAIL OUTBOX FUNCTIONS (Reliable Delivery)
# ============================================

def queue_email(
    email_type: str,
    recipients: Union[str, List[str]],
    subject: str,
    text_content: Optional[str] = None,
    html_content: Optional[str] = None,
    attachments: Optional[List[Dict]] = None,
    context: Optional[Dict] = None,
    guild_id: Optional[int] = None
) -> int:
    """
    Queue an email for reliable delivery via the outbox pattern.
    Returns the outbox entry ID.
    
    Args:
        email_type: Type of email (e.g., 'shift_report', 'adjustment_request', 'forgot_pin')
        recipients: Email address(es) to send to
        subject: Email subject
        text_content: Plain text body
        html_content: HTML body
        attachments: List of attachment dicts (will be JSON serialized)
        context: Additional context for logging/debugging
        guild_id: Optional guild ID for filtering
    """
    recipient_list = recipients if isinstance(recipients, list) else [recipients]
    
    with _get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO email_outbox (
                guild_id, email_type, recipients, subject, 
                text_content, html_content, attachments_json, context_json,
                status, next_retry_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', NOW())
            RETURNING id
        """, (
            guild_id,
            email_type,
            json.dumps(recipient_list),
            subject,
            text_content,
            html_content,
            json.dumps(attachments) if attachments else None,
            json.dumps(context) if context else None
        ))
        outbox_id = cur.fetchone()['id']
        
    logger.info(f"📬 EMAIL QUEUED: #{outbox_id} [{email_type}] to {recipient_list}")
    log_email_to_file(
        event_type="queued",
        recipients=recipient_list,
        subject=subject,
        context={"outbox_id": outbox_id, "email_type": email_type, **(context or {})}
    )
    return outbox_id


def queue_shift_report_email(
    guild_id: int,
    guild_name: str,
    recipients: Union[str, List[str]],
    csv_content: str,
    report_period: str,
    user_name: Optional[str] = None
) -> int:
    """
    Queue a shift report email with CSV attachment.
    This is the reliable replacement for send_timeclock_report_email.
    """
    csv_base64 = base64.b64encode(csv_content.encode('utf-8')).decode('utf-8')
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"timeclock_report_{guild_name.replace(' ', '_')}_{timestamp}.csv"
    
    subject = f"Timeclock Report - {guild_name} ({report_period})"
    
    text_content = f"""
Timeclock Report for {guild_name}

Report Period: {report_period}
Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}

Please find the attached CSV file containing the timeclock data.

---
On the Clock Discord Bot
    """.strip()
    
    html_content = f"""
<html>
<body>
    <h2>Timeclock Report for {guild_name}</h2>
    
    <p><strong>Report Period:</strong> {report_period}</p>
    <p><strong>Generated:</strong> {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <p>Please find the attached CSV file containing the timeclock data.</p>
    
    <hr>
    <p><em>On the Clock Discord Bot</em></p>
</body>
</html>
    """.strip()
    
    attachments = [{
        "filename": filename,
        "content": csv_base64,
        "contentType": "text/csv",
        "encoding": "base64"
    }]
    
    return queue_email(
        email_type="shift_report",
        recipients=recipients,
        subject=subject,
        text_content=text_content,
        html_content=html_content,
        attachments=attachments,
        context={"guild_name": guild_name, "report_period": report_period, "user_name": user_name},
        guild_id=guild_id
    )


def queue_adjustment_notification_email(
    guild_id: int,
    request_id: int,
    user_id: int,
    request_type: str,
    reason: str
) -> int:
    """
    Queue adjustment notification email for reliable delivery.
    This replaces the blocking send_adjustment_notification_email function.

    Args:
        guild_id: The Discord guild ID
        request_id: The time adjustment request ID
        user_id: The user who submitted the request
        request_type: Type of adjustment (modify_clockin, modify_clockout, etc.)
        reason: Reason provided by the user

    Returns:
        The email_outbox entry ID
    """
    from contextlib import closing

    # Fetch guild name and verified recipients
    with _get_db() as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute(
                """SELECT email_address FROM report_recipients
                   WHERE guild_id = %s AND recipient_type = 'email'
                   AND verification_status = 'verified'""",
                (guild_id,)
            )
            recipients = [row['email_address'] for row in cursor.fetchall()]

            if not recipients:
                logger.info(f"No verified recipients for guild {guild_id}, skipping email queue")
                return 0

            cursor.execute(
                "SELECT name FROM guild_settings WHERE guild_id = %s",
                (guild_id,)
            )
            guild_row = cursor.fetchone()
            guild_name = guild_row['name'] if guild_row else f"Server {guild_id}"

    # Format request type for display
    request_type_labels = {
        'modify_clockin': 'Modify Clock-In Time',
        'modify_clockout': 'Modify Clock-Out Time',
        'add_session': 'Add Missing Session',
        'delete_session': 'Delete Session'
    }
    request_label = request_type_labels.get(request_type, request_type)

    # Build email content
    subject = f"Time Adjustment Request - {guild_name}"
    text_content = f"""A new time adjustment request has been submitted.

Server: {guild_name}
Request Type: {request_label}
User ID: {user_id}

Please review this request in the dashboard.

- Time Warden Bot"""

    # Queue the email using existing outbox system
    return queue_email(
        email_type="adjustment_notification",
        recipients=recipients,
        subject=subject,
        text_content=text_content,
        context={
            "guild_name": guild_name,
            "request_type": request_type,
            "request_id": request_id,
            "user_id": user_id
        },
        guild_id=guild_id
    )


async def process_outbox_emails(batch_size: int = 10) -> Dict:
    """
    Process pending emails from the outbox with retry logic.
    Should be called periodically by a scheduler.
    
    Returns stats on processed emails.
    """
    stats = {"processed": 0, "sent": 0, "failed": 0, "retried": 0}
    
    try:
        with _get_db() as conn:
            cur = conn.cursor()
            
            # Get emails ready to process
            cur.execute("""
                SELECT * FROM email_outbox
                WHERE status IN ('pending', 'retry')
                  AND next_retry_at <= NOW()
                ORDER BY created_at ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
            """, (batch_size,))
            
            emails = cur.fetchall()
            
            for email in emails:
                stats["processed"] += 1
                outbox_id = email['id']
                
                try:
                    recipients = json.loads(email['recipients'])
                    attachments = json.loads(email['attachments_json']) if email['attachments_json'] else None
                    
                    # Send the email
                    await email_sender.send_email(
                        to=recipients,
                        subject=email['subject'],
                        text=email['text_content'],
                        html=email['html_content'],
                        attachments=attachments
                    )
                    
                    # Mark as sent
                    cur.execute("""
                        UPDATE email_outbox
                        SET status = 'sent', sent_at = NOW(), last_attempt_at = NOW()
                        WHERE id = %s
                    """, (outbox_id,))
                    conn.commit()
                    
                    stats["sent"] += 1
                    logger.info(f"✅ EMAIL SENT: #{outbox_id} [{email['email_type']}]")
                    
                except Exception as e:
                    error_msg = str(e)[:500]
                    attempts = email['attempts'] + 1
                    max_attempts = email['max_attempts']
                    
                    if attempts >= max_attempts:
                        # Mark as permanently failed
                        cur.execute("""
                            UPDATE email_outbox
                            SET status = 'failed', attempts = %s, last_attempt_at = NOW(), last_error = %s
                            WHERE id = %s
                        """, (attempts, error_msg, outbox_id))
                        conn.commit()
                        
                        stats["failed"] += 1
                        logger.error(f"❌ EMAIL FAILED PERMANENTLY: #{outbox_id} after {attempts} attempts: {error_msg}")
                        log_email_to_file(
                            event_type="failed_permanently",
                            recipients=json.loads(email['recipients']),
                            subject=email['subject'],
                            success=False,
                            error=error_msg,
                            context={"outbox_id": outbox_id, "attempts": attempts}
                        )
                    else:
                        # Schedule retry with exponential backoff
                        backoff_minutes = min(2 ** attempts, 60)  # 2, 4, 8... max 60 min
                        next_retry = datetime.now(timezone.utc) + timedelta(minutes=backoff_minutes)
                        
                        cur.execute("""
                            UPDATE email_outbox
                            SET status = 'retry', attempts = %s, last_attempt_at = NOW(), 
                                last_error = %s, next_retry_at = %s
                            WHERE id = %s
                        """, (attempts, error_msg, next_retry, outbox_id))
                        conn.commit()
                        
                        stats["retried"] += 1
                        logger.warning(f"⏳ EMAIL RETRY SCHEDULED: #{outbox_id} attempt {attempts}/{max_attempts}, next retry in {backoff_minutes} min")
                        
    except Exception as e:
        logger.error(f"❌ Error processing email outbox: {e}")
    
    return stats


def get_outbox_stats(guild_id: Optional[int] = None) -> Dict:
    """Get statistics about the email outbox for monitoring"""
    with _get_db() as conn:
        cur = conn.cursor()
        
        base_where = "WHERE guild_id = %s" if guild_id else "WHERE 1=1"
        params = (guild_id,) if guild_id else ()
        
        cur.execute(f"""
            SELECT 
                status,
                COUNT(*) as count
            FROM email_outbox
            {base_where}
            GROUP BY status
        """, params)
        
        by_status = {row['status']: row['count'] for row in cur.fetchall()}
        
        cur.execute(f"""
            SELECT COUNT(*) as count FROM email_outbox 
            {base_where} AND status IN ('pending', 'retry') AND next_retry_at <= NOW()
        """, params)
        ready_to_send = cur.fetchone()['count']
        
        return {
            "pending": by_status.get('pending', 0),
            "retry": by_status.get('retry', 0),
            "sent": by_status.get('sent', 0),
            "failed": by_status.get('failed', 0),
            "ready_to_send": ready_to_send
        }


# Convenience functions for easy import (legacy compatibility)
async def send_email(to: Union[str, List[str]], subject: str, text: Optional[str] = None, html: Optional[str] = None) -> Dict:
    """Send a simple email directly (use queue_email for reliable delivery)"""
    return await email_sender.send_email(to=to, subject=subject, text=text, html=html)

async def send_timeclock_report_email(to: Union[str, List[str]], guild_name: str, csv_content: str, report_period: str) -> Dict:
    """Send timeclock report directly (use queue_shift_report_email for reliable delivery)"""
    return await email_sender.send_timeclock_report(to=to, guild_name=guild_name, csv_content=csv_content, report_period=report_period)