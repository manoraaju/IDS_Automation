import re
text = 'event MMS_write_request(c: connection, itemId: string, value: bool){' \
       'if (itemId == %(assignment_1)s) {if (c$id$orig_h == "172.18.5.60" && c$id$orig_d == "172.16.4.41")' \
       '{%(guard_1)s = value;' \
       'update_precond();' \
       '}' \
       'else{' \
       'Raise alarm;' \
       '}' \
       '}}'
x1 = re.findall(r'\{(.*?)\}', text)
print(x1)