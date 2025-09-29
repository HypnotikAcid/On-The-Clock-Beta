# Email utility for On the Clock Discord Bot
# Based on Replit Mail integration (blueprint:replitmail)

import os
import json
import base64
import asyncio
import aiohttp
from typing import List, Dict, Optional, Union
from datetime import datetime

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
        payload = {
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
        
        headers = {
            "Content-Type": "application/json",
            "X_REPLIT_TOKEN": self.auth_token
        }
        
        async with aiohttp.ClientSession() as session:
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
                        raise Exception(f"Email send failed: {error_message}")
                    
                    result = await response.json()
                    return result
                    
            except aiohttp.ClientError as e:
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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"timeclock_report_{guild_name}_{timestamp}.csv"
        
        # Prepare email content
        subject = f"Timeclock Report - {guild_name} ({report_period})"
        
        text_content = f"""
Timeclock Report for {guild_name}

Report Period: {report_period}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Please find the attached CSV file containing the timeclock data.

---
On the Clock Discord Bot
        """.strip()
        
        html_content = f"""
<html>
<body>
    <h2>Timeclock Report for {guild_name}</h2>
    
    <p><strong>Report Period:</strong> {report_period}</p>
    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
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

# Convenience functions for easy import
async def send_email(to: Union[str, List[str]], subject: str, text: Optional[str] = None, html: Optional[str] = None) -> Dict:
    """Send a simple email"""
    return await email_sender.send_email(to=to, subject=subject, text=text, html=html)

async def send_timeclock_report_email(to: Union[str, List[str]], guild_name: str, csv_content: str, report_period: str) -> Dict:
    """Send timeclock report with CSV attachment"""
    return await email_sender.send_timeclock_report(to=to, guild_name=guild_name, csv_content=csv_content, report_period=report_period)