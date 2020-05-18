
def get_static_block_from_file(path):
    with open(path, 'r') as f:
        return f.read()

def get_colorbox_for_cvss(score, severity):
    severity = severity.lower()
    color = 'Green'
    if severity == 'low':
        color = 'GreenYellow'
    elif severity == 'medium':
        color = 'Orange'
    elif severity == 'high':
        color = 'RedOrange'
    elif severity == 'critical':
        color = 'Red'
    return '\colorbox{{{}}}{{{} {}}}'.format(color, score, severity)

