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
                        temp_dict["pre_guard_raw"] = pre_guard_raw
                        temp_dict["pre_sync_raw"] = pre_sync_raw
                        temp_dict["pre_assignment_raw"] = pre_assign_raw
                        temp_dict["pre_assignment_vars"] = self.process_assign_to_Vars(pre_assign_raw)
                        temp_dict["post_guard_raw"] = post_guard_raw
                        temp_dict["post_sync_raw"] = post_sync_raw
                        temp_dict["post_assignment_raw"] = post_assign_raw
                        temp_dict["post_assignment_vars"] = self.process_assign_to_Vars(post_assign_raw)
                        temp_dict["post_guard_cond"] = self.process_postcond_guard(post_guard_raw)
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



    def get_attributes(self):
        element = self.node
        if element is None:
            # If there is no element in the elements variable
            print("Element is empty for name {}".format(self.name))
        try:
            attrib_list = [el.attrib.get('kind') for el in element.findall('.//label')]
            attrib_list = list(dict.fromkeys(attrib_list)) ## Remove duplicates
            return attrib_list

        except:
            # If there is no "kind" in the element
            print("No 'kind' present for name {}".format(self.name))

    def get_attribute_values(self, attrib_name):
    ## Storing the values of 'kind' into a dictionary named self.attribute_values
        for name in attrib_name:
            self.attribute_values[name] = ""
        element = self.node
        try:
            for key in self.attribute_values:
                print(key)
                elements_text = [e.text for e in element.findall(".//*[@kind='{}']".format(key))]
                elements_text = list(dict.fromkeys(elements_text))  ## Remove duplicates
                self.attribute_values[key] = elements_text
        except:
            # There is no attribute name in "kind" for the given element
            print("Error in finding attribute values/text for a 'kind' ")

    def process_attribute_values(self):
        bool_format_list = ["True","true","False","false"]
        operator_format_list = '<(?!=)|<=|==|=(?!=)|>(?!=)|>='
        # bool_format_list = "[==, !=]*True|true|False|false"
        for key in self.attribute_values:
            processing_list = self.attribute_values[key]
            ## Remove white spaces
            processing_list = [re.sub(" ","", var) for var in processing_list if var is not None]
            ## Remove None
            processing_list = [var for var in processing_list if var is not None]
            ## Split by operator signs
            processing_list = [re.split(operator_format_list, var) for var in processing_list]
            processing_list = list(chain(*processing_list))
            ## Remove booleans
            processing_list = [var for var in processing_list if var not in bool_format_list]
            self.attribute_values[key] = processing_list

        ## Remove duplicates from "assignment" if it is present in "guard"
        assignment_list = self.attribute_values["assignment"]
        guard_list = self.attribute_values["guard"]
        assignment_list = [var for var in assignment_list if var not in guard_list]
        print(assignment_list)


xml_names = get_names(root_xml)
xml_dict = {}
for name in xml_names:
    xml_dict[name]=xml_data(name)
    xml_dict[name].get_values()
    attribute_list = xml_dict[name].get_attributes()
    xml_dict[name].get_attribute_values(attribute_list)
    xml_dict[name].process_attribute_values()
    print(attribute_list)
    print("Checkpoint")