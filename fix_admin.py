import sys

with open(r'c:\Dev\TimeWarden\bot\cogs\admin_cmds.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_context_menus = False

for line in lines:
    if line.strip() == '@app_commands.command(name="clock", description="Open your personal timeclock hub")':
        in_context_menus = True
        continue

    if line.strip() == '@app_commands.context_menu(name="View Hours")':
        in_context_menus = True

    if line.strip() == 'async def setup(bot):':
        in_context_menus = False
        new_lines.append(line)
        continue

    if in_context_menus:
        if line.startswith('    '):
            line = line[4:] 
        
        if line.startswith('async def context_'):
            line = line.replace('(self, interaction:', '(interaction:')
            
    new_lines.append(line)

for i, line in enumerate(new_lines):
    if line.strip() == 'async def setup(bot):':
        additions = [
            '    bot.tree.add_command(context_view_hours)\n',
            '    bot.tree.add_command(context_force_clockout)\n',
            '    bot.tree.add_command(context_ban_user)\n',
            '    bot.tree.add_command(context_view_profile)\n',
            '    bot.tree.add_command(context_send_shift_report)\n'
        ]
        new_lines.insert(i + 2, ''.join(additions))
        break

with open(r'c:\Dev\TimeWarden\bot\cogs\admin_cmds.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print('Fixed context menus in admin_cmds.py')
