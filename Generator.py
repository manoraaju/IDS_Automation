# Library imports
import os
import xml.etree.ElementTree as ET
import lxml.etree
import re
from itertools import chain



xml_file = lxml.etree.parse("testing.xml")
root_xml = xml_file.getroot()

# Function to get names of templates
def get_names(xml):
    names = []
    for elem in xml.findall(".//template/name"):
        names.append(elem.text)
        #print(elem.text)
    return names

class xml_data():
    def __init__(self, name):
        self.name = name
        self.node = root_xml.find(".//template[name='{}']".format(self.name))
        self.attribute_values = {}
        self.values = []
        self.global_variables = []
        self.MMS_mapping_zeek =[]

    def get_values(self):
        element = self.node
        if element is None:
            # If there is no element in the elements variable
            print("Element is empty for name {}".format(self.name))
        pre_condition_list = element.xpath(".//*[contains(text(), '?')]/..")
        post_condition_list = element.xpath(".//*[contains(text(), '!')][not(contains(text(), '!='))]/..")
        counter = 0
        for e1 in pre_condition_list:
            counter = counter + 1
            temp_dict = {}
            #print([s.text for s in e.findall('.//label')])
            sync_string = ['?','!']
            check_sync = lambda t: True if any(x in t for x in sync_string) else False
            pre_sync_raw = e1.find(".//*[@kind='{}']".format('synchronisation')).text
            pre_assign_raw = e1.find(".//*[@kind='{}']".format('assignment')).text
            pre_guard_raw = e1.find(".//*[@kind='{}']".format('guard')).text
            check_pre_sync = check_sync(pre_sync_raw)
            pre_assignment_vars = self.process_text_tolist(pre_assign_raw)
            for e2 in post_condition_list:
                post_sync_raw = e2.find(".//*[@kind='{}']".format('synchronisation')).text
                post_assign_raw = e2.find(".//*[@kind='{}']".format('assignment')).text
                post_guard_raw = e2.find(".//*[@kind='{}']".format('guard')).text
                check_post_sync = check_sync(post_sync_raw)
                post_guard_vars = self.process_text_tolist(post_guard_raw)

                if check_post_sync and check_pre_sync:
                    if any(map(lambda v: v in pre_assignment_vars, post_guard_vars)):
                        temp_dict["name"] = "precond_{}".format(counter)
                        temp_dict["counter"] = counter
                        temp_dict["pre_guard_raw"] = pre_guard_raw
                        temp_dict["pre_sync_raw"] = pre_sync_raw
                        temp_dict["pre_assignment_raw"] = pre_assign_raw
                        temp_dict["pre_assignment_vars"] = self.process_assign_to_Vars(pre_assign_raw)
                        temp_dict["post_guard_raw"] = post_guard_raw
                        temp_dict["post_sync_raw"] = post_sync_raw
                        temp_dict["post_assignment_raw"] = post_assign_raw
                        temp_dict["post_assignment_vars"] = self.process_assign_to_Vars(post_assign_raw)
                        temp_dict["post_guard_cond"] = self.process_postcond_guard(post_guard_raw)
                        temp_dict["post_assign_check"] = self.process_postcond_assign_tocheck(post_assign_raw)
                        self.values.append(temp_dict)


    def process_text_tolist(self, txt):
        processing_list = txt
        bool_format_list = ["True", "true", "False", "false"]
        operator_format_list = '<(?!=)|<=|==|=(?!=)|>(?!=)|>=|,'
        # bool_format_list = "[==, !=]*True|true|False|false"
        if processing_list is None or processing_list is "" or processing_list is " ":
            return 0
        ## Remove white spaces
        processing_list = re.sub(" ", "", processing_list)
        ## Split by operator signs
        processing_list = re.split(operator_format_list, processing_list)
        ## Remove booleans
        processing_list = [var for var in processing_list if var not in bool_format_list]
        return processing_list

    def process_postcond_guard(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(",", processing_list)
        processing_list = " && ".join(processing_list)
        return processing_list

    def process_precond_assign_tolist(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(",", processing_list)
        processing_list = " && ".join(processing_list)
        return processing_list

    def process_assign_to_Vars(self, txt):
        processing_list = txt
        operator_format_list = '<(?!=)|<=|=(?!=)|>(?!=)|>='
        ## Split by ','
        processing_list = re.split(",", processing_list)
        processing_list = [re.split(operator_format_list, var) for var in processing_list]
        return processing_list

    def process_postcond_assign_tocheck(self, txt):
        processing_list = txt
        ## Split by ','
        processing_list = re.split(",", processing_list)
        processing_list = " && ".join(processing_list)
        processing_list = re.sub("=", "==", processing_list)
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
            temp_dict["post_guard_cond"] = dict["post_guard_cond"]  ##
            temp_dict["post_assign_check"] = dict["post_assign_check"]  ##
            temp_dict["counter"] = dict["counter"]
            self.MMS_mapping_zeek.append(temp_dict)

def create_event_MMS_write(mapping_dict):
    init_text = "\n\nevent MMS_write_request(c: connection, itemId: string, value: bool)\n{%s\n}\n"
    loop_text = (
    '''
	if (itemId == %(itemID)s)
	{
		if (c$id$orig_h == %(IP_ori)s && c$id$orig_d == %(IP_dst)s)
		{
			%(Var_1)s = value;
			update_precond();
		}
		else
		{
			Raise alarm;
		}
	}           
	''')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text%dict)
    init_text = init_text%("".join(temp_list))
    return init_text

def create_event_MMS_read(mapping_dict):
    init_text = "\n\nevent MMS_read_request(c: connection, itemId: string, value: bool)\n{%s\n}"
    loop_text = (
    '''
    if (itemId == %(itemID)s)
    {
        if (c$id$orig_h == %(IP_ori)s && c$id$orig_d == %(IP_dst)s)
        {
            %(Var_1)s = value;
            update_precond();
        }
        else
        {
            Raise alarm;
        }
    }           
    ''')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    return init_text

def create_function_update_precond(mapping_dict):
    init_text = "\n\nfunction update_precond()\n{%s\n}"
    loop_text = (
    '''
    if (%(post_guard_cond)s)
        {
            %(name)s = %(Var_1)s;
            if (!timer_enable_MODBUS1)
            {
                schedule timer_period_MODBUS{timer_finish_MODBUS%(counter)s()};
                timer_enable_MODBUS%(counter)s=true;
            }
        }
    ''')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    return init_text

def create_function_process_modbus(mapping_dict):
    init_text = "\n\nfunction process_MODBUS()\n{%s\n}"
    loop_text = (
    '''
    if %(name)s{
        timer_enable_MODBUS%(counter)s = false;
        VSD1_Command2_old = VSD1_Command2;
        if %(post_assign_check)s {
            break;
        }
        raise alarm;
    }
    ''')
    temp_list = []
    for dict in mapping_dict:
        temp_list.append(loop_text % dict)
    init_text = init_text % ("".join(temp_list))
    return init_text

def create_event_modbus(mapping_dict):
    loop_text = (
'''
\n\nevent timer_finish_MODBUS%(counter)s()
{
    if (timer_enable_MODBUS%(counter)s)
    {
        raise Deletion/Delay alarm;
    }
}''')
    temp_list = []
    for dict in mapping_dict:
        txt = loop_text % dict
        temp_list.append(txt)
    return "".join(temp_list)

def get_global_vars(code):
    processor = code.splitlines()
    global_variables = []
    for word in processor:
        xx = re.findall("=?==", word)

        if "=" in word:
            if "==" not in word:
                word = word.replace("\t","")
                word = word.replace(" ", "")
                word = word.split("=")
                global_variables.append("global "+word[0]+";")
    global_variables = (list(dict.fromkeys(global_variables)))
    return ("\n".join(global_variables))



xml_names = get_names(root_xml)
xml_dict = {}
for name in xml_names:
    xml_dict[name]=xml_data(name)
    xml_dict[name].get_values()
    xml_dict[name].make_global_vars()
    xml_dict[name].create_MMS_mapping_zeek()

t1 = create_event_MMS_write(xml_dict["SPLC"].MMS_mapping_zeek)
t2 = create_event_MMS_read(xml_dict["SPLC"].MMS_mapping_zeek)
t3 = create_function_update_precond(xml_dict["SPLC"].MMS_mapping_zeek)
t4 = create_function_process_modbus(xml_dict["SPLC"].MMS_mapping_zeek)
t5 = create_event_modbus(xml_dict["SPLC"].MMS_mapping_zeek)
processing_code = t1 + t2 + t3 + t4 + t5
t6 = get_global_vars(processing_code)
processing_code = t6 + t1 + t2 + t3 + t4 + t5
f = open("demofile.txt", "w")
f.write(processing_code)
f.close()
