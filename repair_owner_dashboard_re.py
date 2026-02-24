import re

file_path = r'c:\Dev\TimeWarden\templates\owner_dashboard.html'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Pattern 1: Bot Access PAID
content = re.sub(
    r"if \(server\.bot_access\) badges\.push\('<span\s+style=\"background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">PAID</span>'\);",
    r"if (server.bot_access) badges.push('<span style=\"background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">PAID</span>');",
    content
)

# Pattern 2: Server Granted Source
content = re.sub(
    r"if \(server\.granted\) badges\.push\(`<span\s+style=\"background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">\$\{server\.source\s+=== 'stripe' \? 'STRIPE' : 'GRANTED'\}</span>`\);",
    r"if (server.granted) badges.push(`<span style=\"background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">${server.source === 'stripe' ? 'STRIPE' : 'GRANTED'}</span>`);",
    content
)

# Pattern 3: Server Retention
content = re.sub(
    r"if \(server\.retention\) badges\.push\(`<span\s+style=\"background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">\$\{server\.retention\.toUpperCase\(\)\}</span>`\);",
    r"if (server.retention) badges.push(`<span style=\"background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">${server.retention.toUpperCase()}</span>`);",
    content
)

# Pattern 4: Historical Left
content = re.sub(
    r"if \(isHistorical\) badges\.push\(`<span\s+style=\"background: #484f58; color: #8B949E; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">Left\s+\$\{server\.left_at \|\| 'unknown'\}</span>`\);",
    r"if (isHistorical) badges.push(`<span style=\"background: #484f58; color: #8B949E; padding: 2px 6px; border-radius: 4px; font-size: 10px;\">Left ${server.left_at || 'unknown'}</span>`);",
    content
)

# Pattern 5: render onClickAction
content = re.sub(
    r"const onClickAction = `selectServer\('\$\{server\.guild_id\}', '\$\{safeName\}', \$\{botAccessStr\},\s+'\$\{server\.retention \|\| ''\}', \$\{grantedStr\}, '\$\{server\.source \|\| ''\}'\)`;",
    r"const onClickAction = `selectServer('${server.guild_id}', '${safeName}', ${botAccessStr}, '${server.retention || \'\'}', ${grantedStr}, '${server.source || \'\'}')`;",
    content
)


with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("regex cleanup complete")
