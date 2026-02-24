import re

file_path = r'c:\Dev\TimeWarden\templates\owner_dashboard.html'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix renderServerOption block
bad_render_block = """                        if (server.bot_access) badges.push('<span
                            style="background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">PAID</span>');
                        if (server.granted) badges.push(`<span
                            style="background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${server.source
                            === 'stripe' ? 'STRIPE' : 'GRANTED'}</span>`);
                        if (server.retention) badges.push(`<span
                            style="background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${server.retention.toUpperCase()}</span>`);
                        if (isHistorical) badges.push(`<span
                            style="background: #484f58; color: #8B949E; padding: 2px 6px; border-radius: 4px; font-size: 10px;">Left
                            ${server.left_at || 'unknown'}</span>`);

                        const safeName = escapeHtml(server.name).replace(/'/g, "\\\\\\'").replace(/"/g, '&quot;');
                        const botAccessStr = server.bot_access ? 'true' : 'false';
                        const grantedStr = server.granted ? 'true' : 'false';
                        const onClickAction = `selectServer('${server.guild_id}', '${safeName}', ${botAccessStr},
                        '${server.retention || ''}', ${grantedStr}, '${server.source || ''}')`;"""

good_render_block = """                        if (server.bot_access) badges.push('<span style="background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">PAID</span>');
                        if (server.granted) badges.push(`<span style="background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${server.source === 'stripe' ? 'STRIPE' : 'GRANTED'}</span>`);
                        if (server.retention) badges.push(`<span style="background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${server.retention.toUpperCase()}</span>`);
                        if (isHistorical) badges.push(`<span style="background: #484f58; color: #8B949E; padding: 2px 6px; border-radius: 4px; font-size: 10px;">Left ${server.left_at || 'unknown'}</span>`);

                        const safeName = escapeHtml(server.name).replace(/'/g, "\\\\'").replace(/"/g, '&quot;');
                        const botAccessStr = server.bot_access ? 'true' : 'false';
                        const grantedStr = server.granted ? 'true' : 'false';
                        const onClickAction = `selectServer('${server.guild_id}', '${safeName}', ${botAccessStr}, '${server.retention || ''}', ${grantedStr}, '${server.source || ''}')`;"""

# Fix selectServer block
bad_select_block = """                        if (botAccess) badges.push('<span
                            style="background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">PAID</span>');
                        if (granted) badges.push(`<span
                            style="background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${source
                            === 'stripe' ? 'STRIPE' : 'GRANTED'}</span>`);
                        if (retention) badges.push(`<span
                            style="background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${retention.toUpperCase()}</span>`);

                        document.getElementById('selectedServerBadges').innerHTML = `<span
                            style="color: #6E7681; font-size: 11px; margin-right: 8px;">${guildId}</span>` +
                        badges.join(' ');"""

good_select_block = """                        if (botAccess) badges.push('<span style="background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">PAID</span>');
                        if (granted) badges.push(`<span style="background: #6e40c9; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${source === 'stripe' ? 'STRIPE' : 'GRANTED'}</span>`);
                        if (retention) badges.push(`<span style="background: #1f6feb; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${retention.toUpperCase()}</span>`);

                        document.getElementById('selectedServerBadges').innerHTML = `<span style="color: #6E7681; font-size: 11px; margin-right: 8px;">${guildId}</span>` + badges.join(' ');"""


content = content.replace(bad_render_block, good_render_block)
content = content.replace(bad_select_block, good_select_block)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("HTML structure successfully rebuilt without syntax errors.")
