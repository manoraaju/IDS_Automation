# Library imports
import os
import xml.etree.ElementTree as ET
import lxml.etree
import re
from itertools import chain

xml_file = lxml.etree.parse("Uppaal_Load Sharing2.xml")
#xml_file = lxml.etree.parse("testing.xml")
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
            pre_assign_raw = self.process_assignment_raw(pre_assign_raw)
            check_pre_sync = check_sync(pre_sync_raw)
            pre_assignment_vars = self.process_text_tolist(pre_assign_raw)
            for post_elem in post_condition_list:
                post_sync_raw = post_elem.find(".//*[@kind='{}']".format('synchronisation')).text
                post_assign_raw = post_elem.find(".//*[@kind='{}']".format('assignment')).text
                post_assign_raw = self.process_assignment_raw(post_assign_raw)
                post_guard_raw = post_elem.find(".//*[@kind='{}']".format('guard')).text
                post_guard_raw = self.process_guard_raw(post_guard_raw)
                check_post_sync = check_sync(post_sync_raw)
                post_guard_vars = self.process_text_tolist(post_guard_raw)

                if check_post_sync and check_pre_sync:
                    print(pre_assignment_vars, post_guard_vars)
                    if any(map(lambda v: v in pre_assignment_vars, post_guard_vars)):
                        counter = counter + 1
                        temp_dict["name"] = "precond_{}".format(counter)
                        temp_dict["counter"] = counter
                        temp_dict["pre_assignment_vars"] = self.process_assign_to_variables(pre_assign_raw)
                        temp_dict["post_assignment_vars"] = self.process_assign_to_variables(post_assign_raw)
                        temp_dict["post_guard_cond"] = self.process_guard(post_guard_raw)
                        temp_dict["post_assign_check"] = self.process_postcond_assign_tocheck(post_assign_raw)
                        temp_dict["timer_flag"] = True
                        temp_dict["timer_text"] = "{\n\t\t\ttimer_modbus%s = T;" \
                                                  "\n\t\t\tschedule timer_period_MODBUS3 " \
                                                  "{timer_finish_MODBUS%s()};\n\t\t\t}" %(counter,counter)
                        temp_dict["timer_enable"]= "timer_modbus%s = T"%counter
                        temp_dict["timer_disable"] = "timer_modbus%s = F" % counter
                        temp_dict["timer_enable_check"] = "if(timer_modbus%s == T)" % counter

                        self.values.append(temp_dict)

        ##================================================================

        all_post_guard_vars = []
        for post_elem in post_condition_list:
            post_guard_raw = post_elem.find(".//*[@kind='{}']".format('guard')).text
            post_guard_raw = self.process_guard_raw(post_guard_raw)
            all_post_guard_vars.append(self.process_text_tolist(post_guard_raw))

        all_post_guard_vars = [val for sublist in all_post_guard_vars for val in sublist]
        counter = 0
        for pre_elem in pre_condition_list:
            temp_dict = {}
            pre_assign_raw = pre_elem.find(".//*[@kind='{}']".format('assignment')).text
            pre_assign_raw = self.process_assignment_raw(pre_assign_raw)
            if not any(ext in pre_assign_raw for ext in all_post_guard_vars):
                counter = counter + 1
                temp_dict["name"] = "updates_{}".format(counter)
                temp_dict["counter"] = counter
                temp_dict["pre_assignment_vars"] = self.process_assign_to_variables(pre_assign_raw)
                temp_dict["timer_flag"] = False
                self.values.append(temp_dict)
        ##==========
        self.update_operations()

    def in_declaration(self):
        print(1)

    #Find target from the given element's source
    def find_next_hop(self, element):
        elem_target = (element.find(".//target")).attrib["ref"]
        finder = (self.node.findall(".//source[@ref='{}']/..".format(elem_target)))
        if len(finder) == 0:
            print("No targets found!")
            return 0, 0
            # print(self.vector)
        else:
            return finder, 1

    def update_operations(self):
        element = self.node
        operations_list = []
        if element is None:
            # If there is no element in the elements variable
            print("Element is empty for name {}".format(self.name))

        transitions = element.findall(".//transition")
        non_sync_transitions = []
        for t in transitions:
            #if len((t.xpath('.//*[contains(text(),"!")]'))) != 0 or len((t.xpath('.//*[contains(text(),"?")]'))) != 0:
            if len((t.xpath('.//*[contains(text(),"!")]'))) == 0 and len((t.xpath('.//*[contains(text(),"?")]'))) == 0:
                    non_sync_transitions.append(t)

        if len(t) == 0:
            self.MMS_mapping_update["update_operation"]= ""

        else:
            temp_list = []
            for elem in non_sync_transitions:
                try:
                    guard = elem.find(".//*[@kind='{}']".format('guard')).text
                    guard = self.process_guard_raw(guard)
                except:
                    guard = None
                assignment = elem.find(".//*[@kind='{}']".format('assignment')).text
                if guard is None:
                    assignment = self.process_assignment_raw(assignment)
                    temp_list.append(assignment)
                else:
                    guard = self.process_guard(guard)
                    assignment = self.process_assignment_raw(assignment)
                    temp_variable = (guard + "\n{%s\n}") %(assignment)
                    #print(temp_variable)
                    temp_list.append(temp_variable)
            self.MMS_mapping_update["update_operation"]= "\n".join(temp_list)


    def process_text_tolist(self, txt):
        processing_list = txt
        bool_format_list = ["True", "true", "False", "false"]
        operator_format_list = '<(?!=)|<=|==|=(?!=)|>(?!=)|>=| and | AND | And | && ,'
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

    def process_guard_raw(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.sub("true|True", "T", processing_list)
        processing_list = re.sub("false|False", "F", processing_list)
        processing_list = re.sub(" and | And | AND", " && ", processing_list)
        processing_list = re.sub(" or | Or | OR", " || ", processing_list)
        processing_list = re.split("&&", processing_list)
        temp_processing_list = []
        for item in processing_list:
            try:
                item = item.strip()
                find_sign = re.search("<(?!=)|(?<!<)(?<!>)(?<!=)=(?!=)|>(?!=)", item).start()
                text_string = item[find_sign+1:].strip()
                if not self.is_numeric(text_string):
                    if not self.is_bool(text_string):
                        if not self.is_arithmetic(text_string):
                            temp_string = item[:find_sign+1] + ' "%s"' % text_string
                            temp_processing_list.append(temp_string)
                        else:
                            temp_processing_list.append(item)
                    else:
                        temp_processing_list.append(item)
                else:
                    temp_processing_list.append(item)
            except:
                print("None found")

            try:
                item = item.strip()
                find_2sign = re.search("<=|>=|==", item).start()
                text_string = item[find_2sign+2:].strip()
                if not self.is_numeric(text_string):
                    if not self.is_bool(text_string):
                        if not self.is_arithmetic(text_string):
                            temp_string = item[:find_2sign + 1] + ' "%s"' % text_string
                            temp_processing_list.append(temp_string)
                        else:
                            temp_processing_list.append(item)
                    else:
                        temp_processing_list.append(item)
                else:
                    temp_processing_list.append(item)
            except:
                print("None found")
        processing_list = " && ".join(temp_processing_list)
        return processing_list

    def process_assignment_raw(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(";", processing_list)
        processing_list = [i.strip() for i in processing_list if i]
        temp_processing_list = []
        for item in processing_list:
            try:
                item = item.strip()
                find_sign = re.search("<(?!=)|(?<!<)(?<!>)(?<!=)=(?!=)|>(?!=)", item).start()
                text_string = item[find_sign+1:].strip()
                if not self.is_numeric(text_string):
                    if not self.is_bool(text_string):
                        if not self.is_arithmetic(text_string):
                            temp_string = item[:find_sign+1] + ' "%s"' % text_string
                            temp_processing_list.append(temp_string)
                        else:
                            temp_processing_list.append(item)
                    else:
                        temp_processing_list.append(item)
                else:
                    temp_processing_list.append(item)
            except:
                print("None found")

            try:
                item = item.strip()
                find_2sign = re.search("<=|>=|==", item).start()
                text_string = item[find_2sign+2:].strip()
                if not self.is_numeric(text_string):
                    if not self.is_bool(text_string):
                        if not self.is_arithmetic(text_string):
                            temp_string = item[:find_2sign + 1] + ' "%s"' % text_string
                            temp_processing_list.append(temp_string)
                        else:
                            temp_processing_list.append(item)
                    else:
                        temp_processing_list.append(item)
                else:
                    temp_processing_list.append(item)
            except:
                print("None found")
        processing_list = ["\n%s;" % item for item in temp_processing_list]
        processing_list = "".join(processing_list)
        return processing_list

    def process_guard(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.sub("true|True", "T", processing_list)
        processing_list = re.sub("false|False", "F", processing_list)
        processing_list = re.sub(" and | And | AND", " && ", processing_list)
        processing_list = "if (%s)" %processing_list
        return processing_list

    def process_assignment(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(";", processing_list)
        processing_list = [i.strip() for i in processing_list if i]
        processing_list = ["\n%s;"%item for item in processing_list]
        processing_list = "".join(processing_list)
        return processing_list

    def process_precond_assign_tolist(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(",", processing_list)
        processing_list = " && ".join(processing_list)
        return processing_list

    def process_assign_to_variables(self, txt):
        processing_list = txt
        operator_format_list = '<(?!=)|<=|=(?!=)|>(?!=)|>='
        processing_list = re.sub("\n", "", processing_list)
        ## Split by ','
        processing_list = re.split(";", processing_list)
        processing_list = [var for var in processing_list if var]
        processing_list = [re.split(operator_format_list, var) for var in processing_list]
        return processing_list

    def process_postcond_assign_tocheck(self, txt):
        processing_list = txt
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
                   {"IP_ori":"172.18.5.60","IP_dst":"172.16.4.41"},
                   {"IP_ori":"172.18.5.60","IP_dst":"172.16.4.41"},]
        counter = 0
        for dict in self.values:
            temp_dict = {}
            for key in dict:
                if key == "pre_assignment_vars":
                    temp_dict["itemID"] = dict[key][0][1]  ## Only one itemID is expected right now
                    temp_dict["Var_1"] = dict[key][0][0]  ## Only one itemID is expected right now
                    temp_dict["IP_ori"] = ip_dict[counter]["IP_ori"]  ##
                    temp_dict["IP_dst"] = ip_dict[counter]["IP_dst"]  ##
                    temp_dict["name"] = dict["name"]  ##
                    temp_dict["counter"] = dict["counter"]

                if dict["timer_flag"] == True:
                    temp_dict["post_guard_cond"] = dict["post_guard_cond"]  ##
                    temp_dict["post_assign_check"] = dict["post_assign_check"]  ##
                    temp_dict["timer_text"] = dict["timer_text"]
                    temp_dict["timer_enable"] = dict["timer_enable"]
                    temp_dict["timer_disable"] = dict["timer_disable"]
                    temp_dict["timer_enable_check"] = dict["timer_enable_check"]
                    temp_dict["timer_flag"] = dict["timer_flag"]

                if dict["timer_flag"] == False:
                    temp_dict["post_guard_cond"] = ""
                    temp_dict["post_assign_check"] = ""
                    temp_dict["timer_text"] = ""
                    temp_dict["timer_enable"] = ""
                    temp_dict["timer_disable"] = ""
                    temp_dict["timer_enable_check"] = ""
                    temp_dict["timer_flag"] = dict["timer_flag"]


            self.MMS_mapping_zeek.append(temp_dict)


xml_template_name = "Template"
#xml_template_name = "SPLC"
processed_xml = xml_data(xml_template_name)
processed_xml.get_values()
processed_xml.create_MMS_mapping_zeek()

def create_event_MMS_read(mapping_dict, update_operation):
    init_text = "\n\nevent MMS_read_request(c: connection, itemId: string, value: bool)\n{%s\n%s\n}"
    loop_text = (
    '\n\tif (itemId == %(itemID)s)'
    '\n\t{'
    '\n\t\tif (c$id$orig_h == %(IP_ori)s)'
    '\n\t\t\t{\n\t\t\t%(Var_1)s = value;'
    '\n\t\t\t%(post_guard_cond)s'
    '%(timer_text)s'
    '\n\t\t}'
    '\n\t}')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list), update_operation["update_operation"])
    print(init_text)
    return init_text

def create_event_modbus_read_registers(mapping_dict):
    init_text =(
    '''
event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
{
    local i = 5;
    if (registers[i] != VSD1_Command2)
    {
        VSD1_Command2=registers[i];
        print "Injection Alarm";
    }
%s\n}
    ''')
    loop_text = (
'''
    %(timer_enable_check)s
    {
        %(post_assign_check)s
        {
            %(timer_disable)s;
            break;
        }
        print "Modification Alarm";
    }
''')
    temp_list = []
    for dict in mapping_dict:
        if dict["timer_flag"]==True:
            temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    print(init_text)
    return init_text

def create_event_timer_finish(mapping_dict):
    loop_text = (
'''
event timer_finish_MODBUS%(counter)s()
{
    %(timer_enable_check)s
    {
        print "Deletion/Delay alarm";
    }
}
''')
    temp_list = []
    for dict in mapping_dict:
        if dict["timer_flag"]==True:
            temp_list.append(loop_text % dict)
    init_text = ("".join(temp_list))
    print(init_text)
    return init_text


t1= create_event_MMS_read(processed_xml.MMS_mapping_zeek, processed_xml.MMS_mapping_update)
t2= create_event_modbus_read_registers(processed_xml.MMS_mapping_zeek)
t3= create_event_timer_finish(processed_xml.MMS_mapping_zeek)

all_txt = t3 + t1 + t2
print(all_txt)