# Library imports
import os
import xml.etree.ElementTree as ET
import lxml.etree
import re
from itertools import chain

#xml_file = lxml.etree.parse("Uppaal_Load Sharing2.xml")
xml_file = lxml.etree.parse("testing.xml")
root_xml = xml_file.getroot()

class xml_data():
    def __init__(self, name):
        self.name = name
        self.node = root_xml.find(".//template[name='{}']".format(self.name))
        self.attribute_values = {}
        self.values = []
        self.global_variables = []
        self.MMS_mapping_zeek =[]
        self.variable_declarations = root_xml.xpath("/nta/declaration/text()")[0]
        self.MMS_mapping_update = {}


    def get_values(self):
        element = self.node
        if element is None:
            # If there is no element in the elements variable
            print("Element is empty for name {}".format(self.name))
        pre_condition_list = element.xpath(".//*[contains(text(), '?')]/..")
        post_condition_list = element.xpath(".//*[contains(text(), '!')][not(contains(text(), '!='))]/..")
        counter = 0
        for pre_element in pre_condition_list:
            temp_dict = {}
            #print([s.text for s in e.findall('.//label')])
            sync_string = ['?','!']
            check_sync = lambda t: True if any(x in t for x in sync_string) else False
            pre_sync_raw = pre_element.find(".//*[@kind='{}']".format('synchronisation')).text
            pre_assign_raw = pre_element.find(".//*[@kind='{}']".format('assignment')).text
            check_pre_sync = check_sync(pre_sync_raw)
            pre_assignment_vars = self.process_text_tolist(pre_assign_raw)
            for post_elem in post_condition_list:
                post_sync_raw = post_elem.find(".//*[@kind='{}']".format('synchronisation')).text
                post_assign_raw = post_elem.find(".//*[@kind='{}']".format('assignment')).text
                post_guard_raw = post_elem.find(".//*[@kind='{}']".format('guard')).text
                check_post_sync = check_sync(post_sync_raw)
                post_guard_vars = self.process_text_tolist(post_guard_raw)

                if check_post_sync and check_pre_sync:
                    print(pre_assignment_vars, post_guard_vars)
                    if any(map(lambda v: v in pre_assignment_vars, post_guard_vars)):
                        counter = counter + 1
                        temp_dict["name"] = "precond_{}".format(counter)
                        temp_dict["counter"] = counter
                        temp_dict["itemID"] = self.get_itemID(pre_assign_raw)
                        temp_dict["itemID_name"] = self.get_idemID_name(pre_assign_raw)
                        temp_dict["precond_guard"] = self.precond_check(counter,post_guard_raw)
                        temp_dict["negate_precond_guard"] = self.precond_check_negate(counter, post_guard_raw)
                        temp_dict["post_assignment"] = self.process_post_assignment(post_assign_raw)
                        temp_dict["post_assignment_guard"] = self.process_postassign_toguard(post_assign_raw)
                        temp_dict["timer_flag"] = True


                        self.values.append(temp_dict)

    def process_text_tolist(self, txt):
        processing_list = txt
        bool_format_list = ["True", "true", "False", "false"]
        operator_format_list = '<(?!=)|<=|==|=(?!=)|>(?!=)|>=| and | AND | And | && '
        and_list = ["and", "And", "AND", "&&"]
        # bool_format_list = "[==, !=]*True|true|False|false"
        if processing_list is None or processing_list is "" or processing_list is " ":
            return 0
        ## Split by operator signs
        processing_list = re.split(operator_format_list, processing_list)
        ## Remove white spaces
        processing_list = [re.sub(" ", "", var) for var in processing_list]
        ## Remove booleans
        processing_list = [var for var in processing_list if var not in bool_format_list]
        ## Remove whitespaces
        processing_list = [var.strip() for var in processing_list]
        return processing_list

    def get_itemID(self, txt):
        processing_list = txt
        processing_list = re.sub("\n", "", processing_list)
        processing_list = re.sub(";", "", processing_list)
        ## Split by ','
        processing_list = re.split("=", processing_list)
        if self.is_bool(processing_list[1]):
            return processing_list[1]
        if self.is_numeric(processing_list[1]):
            return processing_list[1]
        return '"{}"'.format(processing_list[1])

    def get_idemID_name(self, txt):
        processing_list = txt
        processing_list = re.sub("\n", "", processing_list)
        processing_list = re.sub(";", "", processing_list)
        ## Split by ','
        processing_list = re.split("=", processing_list)
        return "{}".format(processing_list[0])

    def precond_check(self, counter, txt):
        processing_list = txt
        b_true_list = ["True", "TRUE", "true", "T"]
        b_false_list = ["False", "FALSE", "false", "F"]
        for b in b_true_list:
            if b in processing_list:
                return "if (precond_{} == {})".format(counter, "T")
        for b in b_false_list:
            if b in processing_list:
                return "if (precond_{} == {})".format(counter, "F")

    def precond_check_negate(self, counter, txt):
        processing_list = txt
        b_true_list = ["True", "TRUE", "true", "T"]
        b_false_list = ["False", "FALSE", "false", "F"]
        for b in b_true_list:
            if b in processing_list:
                return "precond_{} = {}".format(counter, "F")
        for b in b_false_list:
            if b in processing_list:
                return "precond_{} = {}".format(counter, "T")

    def process_post_assignment(self, txt):
        processing_list = txt
        find_hex = re.search("16#", processing_list).start()
        hex_value = processing_list[find_hex+3:]
        int_value = int(hex_value, 16)
        processing_list = processing_list[0:find_hex] + str(int_value)
        return processing_list

    def process_postassign_toguard(self, txt):
        processing_list = self.process_post_assignment(txt)
        ## Split by ','
        processing_list = re.split(";", processing_list)
        processing_list = [i.strip() for i in processing_list if i]
        processing_list = " && ".join(processing_list)
        processing_list = re.sub("=", "==", processing_list)
        processing_list = re.sub("true|True", "T", processing_list)
        processing_list = re.sub("false|False", "F", processing_list)
        processing_list = re.sub(" and | And ", " && ", processing_list)
        processing_list = "if (%s)"% processing_list
        return processing_list

    def make_global_vars(self):
        vars_from_dict = ["pre_assignment_vars", "post_assignment_vars"]
        for dict in self.values:
            for key in dict:
                if key in vars_from_dict:
                    for item in dict[key]:
                        self.global_variables.append("global "+item[0]+";")
        self.global_variables= (list(dict.fromkeys(self.global_variables)))
        ## Additional global variables set based on number of preconditions
        no_of_precond = len(self.values)
        for num in range(no_of_precond):
            self.global_variables.append("global precond_{}".format(num+1)+";")

    def is_bool(self, b):
        b_list = ["True", "TRUE", "true", "False", "FALSE", "false", "T", "F"]
        try:
            if b in b_list:
                return True
        except:
            return False

    def is_numeric(self, b):
        if b.isnumeric():
            return True
        else:
            return False

    def is_arithmetic(self, b):
        arth = ['+', '-', '*', '/']
        check = lambda t: True if any(x in t for x in arth) else False
        return check(b)


    def create_MMS_mapping_zeek(self):
        ## itemID, IP_ori, IP_dst, Var_1,
        ip_dict = [{"IP_ori":"172.18.5.60","IP_dst":"172.16.4.41"},
                   {"IP_ori":"172.16.4.41","IP_dst":"172.18.5.60"},
                   {"IP_ori":"172.18.5.60","IP_dst":"172.16.4.41"},]
        counter = 0
        for dict in self.values:
            temp_dict = {}
            for key in dict:
                temp_dict["name"] = dict["name"]
                temp_dict["counter"] = dict["counter"]
                temp_dict["itemID"] = dict["itemID"]
                temp_dict["itemID_name"] = dict["itemID_name"]
                temp_dict["precond_guard"] = dict["precond_guard"]
                temp_dict["negate_precond_guard"] = dict["negate_precond_guard"]
                temp_dict["post_assignment_guard"] = dict["post_assignment_guard"]
                temp_dict["post_assignment"] = dict["post_assignment"]
                temp_dict["IP_ori"] = ip_dict[counter]["IP_ori"]  ##
                temp_dict["IP_dst"] = ip_dict[counter]["IP_dst"]  ##
                if dict["timer_flag"] == True:
                    temp_dict["timer_text"] = "if (timer_modbus%(counter)s != T) {timer_modbus%(counter)s = T;" \
                                          "schedule timer_period_MODBUS%(counter)s " \
                                          "{timer_finish_MODBUS%(counter)s()};}" % (dict)
                    temp_dict["timer_enable"] = "timer_modbus%(counter)s = T" % dict
                    temp_dict["timer_disable"] = "timer_modbus%(counter)s = F" % dict
                    temp_dict["timer_enable_check"] = "if (timer_modbus%(counter)s == T)" % dict
                    temp_dict["timer_disable_check"] = "if (timer_modbus%(counter)s != T)" % dict

                if dict["timer_flag"] == False:
                    temp_dict["post_guard_cond"] = ""
                    temp_dict["post_assign_check"] = ""
                    temp_dict["timer_text"] = ""
                    temp_dict["timer_enable"] = ""
                    temp_dict["timer_disable"] = ""
                    temp_dict["timer_enable_check"] = ""
                    temp_dict["timer_disable_check"] = ""
                    temp_dict["timer_flag"] = dict["timer_flag"]


            self.MMS_mapping_zeek.append(temp_dict)


#xml_template_name = "Template"
xml_template_name = "SPLC"
processed_xml = xml_data(xml_template_name)
processed_xml.get_values()
processed_xml.create_MMS_mapping_zeek()

def create_event_MMS_read(mapping_dict, update_operation):
    init_text = "event read_response(c: connection, invokeID: count, itemID: string, " \
                "boolean_result: bool){%s}"
    loop_text = (
    'if (itemId == %(itemID)s)'
    '{'
    'if (c$id$orig_h == %(IP_ori)s)'
    '{%(name)s = value;'
    '%(timer_text)s'
    '}'
    '}')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    #print(init_text)
    return init_text

def create_event_MMS_write(mapping_dict, update_operation):
    init_text = "event write_request(c: connection, domainID: string, itemID: string, " \
                "boolean_result: bool){%s}"
    loop_text = (
    'if (itemId == %(itemID)s)'
    '{'
    'if (c$id$orig_h == %(IP_ori)s)'
    '{%(name)s = value;'
    '%(timer_text)s'
    '}'
    '}')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    #print(init_text)
    return init_text

def create_event_modbus_read_registers(mapping_dict):
    init_text =("event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, "
                "start_address: count, registers: ModbusRegisters){%s}")
    loop_text = (
    '%(precond_guard)s'
    "{%(post_assignment_guard)s{%(timer_disable)s;break;}"
    'print "Modification Alarm for %(itemID_name)s";}')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    #print(init_text)
    return init_text

def create_event_timer_finish(mapping_dict):
    loop_text = ('event timer_finish_MODBUS%(counter)s()'
                 '{%(timer_enable_check)s '
                 '{print "Deletion/Delay alarm for %(itemID_name)s";%(timer_disable)s;}}')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = ("".join(temp_list))
    #print(init_text)
    return init_text

def is_bool(b):
    b_list = ["True", "TRUE", "true", "False", "FALSE", "false", "T", "F"]
    try:
        if b in b_list:
            return True
    except:
        return False

def is_numeric(b):
    if b.isnumeric():
        return True
    else:
        return False

def is_arithmetic(b):
    arth = ['+', '-', '*', '/']
    check = lambda t: True if any(x in t for x in arth) else False
    return check(b)

def get_global_variables(code):
    lines = code.split('\n')
    global_variables = []
    #print(lines)
    for line in lines:
        if ";" in line:
            line = line.strip(";")
            line = line.replace(" ", "")
            line = line.replace("\t", "")
            if "schedule" in line:
                reg_ex = re.compile("(?<=schedule).*?(?={)")
                line = reg_ex.findall(line)[0].replace(" ", "")
                global_variables.append("global %s = 0.4 secs;" % line)
            else:
                line = line.split("=")
                if len(line)==2 and "local" not in line[0] and line[0] not in "".join(global_variables):
                    if is_bool(line[1]):
                        global_variables.append("global %s = F;"%line[0])
                    else:
                        global_variables.append("global %s = 0;" % line[0])

    for line in lines:
        if "==" in line:
            line = line.replace(" ", "")
            if_stmt = line[line.find("(") + 1:line.find(")")]
            if_stmt = if_stmt.split("==")
            if is_bool(if_stmt[1]):
                for cnt in range(len(global_variables)):
                    if if_stmt[0] in global_variables[cnt]:
                        global_variables[cnt] = "global %s = F;" % if_stmt[0]
                    else:
                        global_variables.append("global %s = F;" % if_stmt[0])

            if is_numeric(if_stmt[1]):
                for cnt in range(len(global_variables)):
                    if if_stmt[0] in global_variables[cnt]:
                        global_variables[cnt] = "global %s = 0;" % if_stmt[0]
                    else:
                        global_variables.append("global %s = 0;" % if_stmt[0])

    global_variables = list(dict.fromkeys(global_variables))
    return "\n".join(global_variables)

def code_intender(txt):
    new_all_txt1 = []
    tab_counter = 0
    for ch in txt:
        if ch == ";":
            new_all_txt1.append(ch + "\n")
        else:
            new_all_txt1.append(ch)

    new_all_txt1 = "".join(new_all_txt1).split("\n")
    new_all_txt2 = []
    for line in new_all_txt1:
        temp_line = []
        if "schedule" in line:
            new_all_txt2.append(line)
        else:
            for ch in line:
                if ch == "{":
                    temp_line.append("\n" + ("\t" * tab_counter) + ch + "\n")
                    tab_counter = tab_counter + 1
                elif ch == "}":
                    tab_counter = tab_counter - 1
                    temp_line.append(("\t" * tab_counter) + ch + "\n")
                else:
                    temp_line.append(ch)
            new_all_txt2.append("".join(temp_line))

    new_all_txt3 = []
    tab_counter = 0
    for line in new_all_txt2:
        lines_of_line = line.split("\n")
        temp_line = []
        for l2 in lines_of_line:
            if l2.strip("\t") == "{":
                temp_line.append(l2)
                tab_counter = tab_counter + 1
            elif l2.strip("\t") == "}":
                tab_counter = tab_counter - 1
                temp_line.append(l2)
            else:
                temp_line.append(("\t" * (tab_counter)) + l2)
        new_all_txt3.append("\n".join(temp_line))
    return "\n".join(new_all_txt3)

t1= create_event_MMS_read(processed_xml.MMS_mapping_zeek, processed_xml.MMS_mapping_update)
t2= create_event_MMS_write(processed_xml.MMS_mapping_zeek, processed_xml.MMS_mapping_update)
t3= create_event_modbus_read_registers(processed_xml.MMS_mapping_zeek)
t4= create_event_timer_finish(processed_xml.MMS_mapping_zeek)
all_txt = t4 + t1 + t2 + t3
all_txt = code_intender(all_txt)
print(all_txt)

t5 = get_global_variables(all_txt)


all_txt = t5 + all_txt
print("================================================================")
print(all_txt)
print("================================================================")