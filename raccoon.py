#!/usr/bin/env python
"""
    Python Tool designed to aid in performing a basic investigation on provided IP addresses
    Performs WHOIS lookup, Host lookup by IP address, IP Location lookup, and TOR node check
"""
# -*- coding: utf-8 -*-
#
# Raccoon PI - investigates IP addresses -- Version 0.1
# Performs WHOIS lookup, Host lookup by IP address, IP Location lookup, and TOR node check
# - Peter Robards.
#
##########################################################################################
# Whois File Format:
#    Blah Blah Blah
#    KEY:    Value
#    KEY:    Value
#    Blah Blah Blah
#
# Note:
#    freegeoip.app provides a free IP gelocation that allows 15,000 queries per hour
#    TOR Exit node data should be availble here: https://check.torproject.org/torbulkexitlist
#    For Bulk IP lookups WHOIS data is very uneven in terms of Key:value pairs per IP address
#    so individual records could be very different for each IP address.
#
##########################################################################################

__author__ = ["Peter Robards"]
__date__ = "02/28/2021"
__description__ = (
    "Python tool designed to aid in collecting information on provided IP addresses"
)

import os
import re
import sys
import csv
import copy
import json
import socket
import argparse
import subprocess

import requests


################################# Data Validation ########################################


def validate_ip(line):
    """Method to check that input matches a valid IPv4 address"""
    is_valid = ""
    # RegEx to check for valid IPv4 address below.
    # ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
    # Note: ^ $ ensure string matche exactly, 25[ ensures 0 - 255 range
    matched = re.match(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        line,
    )
    if matched:
        # matches a date and adds it to is_valid
        is_valid = matched.group()
    else:
        is_valid = None
    return is_valid


def check_path(file_path):
    """Method to check that provided Directory exists and is valid"""
    if not os.path.exists(file_path):
        print("\n[!] ERROR -> '{}' is NOT a valid file ...\n".format(file_path))
        print("\n******* ******* *******")
        sys.exit(1)


################################# Data Collection ########################################


def perform_whois(target_ip):
    """Method that relies on subprocess to perform a WHOIS lookup on an IP address"""
    whois_results = ""
    # Set time value for whois call in seconds
    time_limit = 180

    ## Text result of the whois is stored in whois_result...
    #  Note: encoding='iso-8859-1' due to French language and its cast of characters...
    cmd = ["whois", "n", "+", target_ip]
    try:
        whois_results = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, encoding="ISO-8859-1", timeout=time_limit
        )
        if "No match for" in whois_results:
            print("\n[!] Processing whois failure on IP: '{}'".format(target_ip))
            print("\t[-] WHOIS Results:\n{}".format(whois_results))
    except subprocess.TimeoutExpired:
        print("\n[!] Processing whois failure on IP: '{}'".format(target_ip))
        print("[-] Timeout triggered after '{}' seconds.\n".format(time_limit))
        whois_results = "whois_data: TIME OUT FAILURE"

    return whois_results


def get_whois_key(text):
    """Method that parses a line of text extracting a key value that appears just before a ':'"""
    is_key = ""
    if text[-1] == ":":
        # Check if the last character in text is a ':'
        # if so, this matches the format of a key value
        is_key = text[:-1]
    else:
        is_key = None
    return is_key


def get_whois_value(text):
    """Parses a line of text extracting any extraneous whitespace characters at the start/end"""
    # Uncomment below for simple debugging purposes
    # print("\n\tBefore VALUE: \'{}\'".format(text))
    whois_value = text.strip()
    # print("\n\tVALUE: \'{}\'".format(whois_value))
    return whois_value


def lookup_host(ip_addr):
    """Returns a tuple with the results from the sockets method: 'gethostbyaddr(ip)'"""
    # TO DO: Create a host class to handle this data
    socket.setdefaulttimeout(3)
    try:
        return socket.gethostbyaddr(ip_addr)
    except socket.herror:
        return None, None, None


def get_host_data(target_ip):
    """
    Returns a dictionary with the source IP address linked to
    the results from the sockets method: 'gethostbyaddr(ip)'
    """
    host_data = {
        "source_ip": target_ip,
        "host_name": None,
        "host_alias": None,
        "host_address_list": None,
    }
    name, alias, address_list = lookup_host(target_ip)
    # Note: lookup_host(target_ip) returns a tuple with
    # the results from the sockets method: 'gethostbyaddr(ip)

    host_data["host_name"] = name
    host_data["host_alias"] = alias
    host_data["host_address_list"] = address_list

    return host_data


def check_tor(target_ip, tor_exit_nodes):
    """Check target IP address against provided list of Known TOR Exit Nodes"""
    results = {}
    # Compare IP to list of known TOR Exit nodes and classify accordingly
    if target_ip in tor_exit_nodes:
        results = {"source_ip": target_ip, "is_TOR": True}
    else:
        results = {"source_ip": target_ip, "is_TOR": False}
    return results


def get_location_data(target_ip):
    """
    Returns JSON Data with location data related to provided IP address
    Relies on 'Free IP Geolocation API' via '"https://freegeoip.app'
    """
    # Note: freegeoip.app provides a free IP gelocation API for software developers.
    # It uses a database of IP addresses that are associated to cities along with other
    # relevant information like time zone, latitude and longitude.
    # You're allowed up to 15,000 queries per hour by default.
    # Once this limit is reached, all of your requests will result in HTTP 403, forbidden,
    # until your quota is cleared.
    # The HTTP API takes GET requests in the following schema:
    # https://freegeoip.app/{format}/{IP_or_hostname}
    # Supported formats are: csv, xml, json and jsonp.
    url = "https://freegeoip.app/json/" + target_ip

    headers = {"accept": "application/json", "content-type": "application/json"}

    response = requests.request("GET", url, headers=headers)
    # response.text should now contain the location data we want in json format
    dict_response = convert_json_to_dict(response.text)
    # Check to make sure dict_response is not empty, if so add source_ip and return
    if not dict_response:
        dict_response["source_ip"] = target_ip
        dict_response["location_data"] = "No Response"
    return dict_response


################################ Build Dictionary ########################################


def convert_json_to_dict(json_data):
    """Converts JSON data containing location info on an IP address to a Python dictionary"""
    loc_dict = {}
    # Replace default key:'ip' with new key:'source_ip' to match the other data
    new_key = "source_ip"
    old_key = "ip"

    try:
        loc_dict = json.loads(json_data)
        loc_dict[new_key] = loc_dict.pop(old_key)

        for current_key in loc_dict.keys():
            if current_key != "source_ip":
                new_key = "ip_" + current_key
                loc_dict[new_key] = loc_dict.pop(current_key)

    except ValueError:  # includes simplejson.decoder.JSONDecodeError
        print("\n[!] ERROR -> Loading Location JSON data has failed")

    return loc_dict


def create_dict(whois_response, target_ip):
    """Creates a Python Dictionary out of a RAW WHOIS text response"""
    current_dict = {}
    for line in whois_response.splitlines():
        current_dict.update({"source_ip": target_ip})
        # Check if the line is just a newline or blank space
        if line not in ("\\n", ""):
            # Split the text by spaces and the grab the first group of characters
            current_line = line.split()[0]
        if current_line:
            # Check group of characters to see if it matches the pattern of a key
            if get_whois_key(current_line):
                current_dict = extract_key_value(current_line, line, current_dict)

    # This handles the lack of response from an error such as whois timeout
    if not current_dict:
        current_dict.update({"source_ip": target_ip})
        current_dict.update({"whois_data": "Not Found"})

    return current_dict


def extract_key_value(current_line, line, current_dict):
    """Extracts the Key:Value pairs of data from a RAW text WHOIS response"""
    # current_line is the part of the string where the key value should be
    # line is the original full line/string potentially holding both key & value
    current_key = get_whois_key(current_line)
    current_value = get_whois_value(line.split(":")[-1])
    # Check if we accidentally truncated a URL mistaking it for a key due to ':'
    # If this is the case, fix it (append http:) and continue processing
    if current_value != "" and current_value[0] == "/":
        current_value = "http:" + current_value
    # Checking for "---" filters out extra formatting characters from 'remarks', et al.
    if current_dict.get(current_key) is None and "---" not in current_value:
        # If key does not already exist & current value is valid: add new key:value pair
        current_dict.update({current_key: current_value})
    else:
        # Since current_key already exists in the dictionary
        # perform final check to catch possible edge cases for possible invalid values
        if current_value != "" and current_value[0] != "-":
            # Check if there are multiple values assigned to current key or only one
            if isinstance(current_dict.get(current_key), list):
                # If current_value is a new value then add it to data
                if current_value not in current_dict.get(current_key):
                    # Appending a single new value to an existing key
                    current_dict[current_key].append(current_value)
            else:
                # current_key contains a list and therefore has multiple values...
                if current_value != current_dict.get(current_key):
                    # Create a temporary list, add the value in our dictionary
                    # and the current_value, then update the current_dict
                    temp_list = []
                    temp_list.append(current_dict.get(current_key))
                    temp_list.append(current_value)
                    current_dict.update({current_key: temp_list})
    return current_dict


def merge_data(dict_data_alpha, dict_data_beta, primary_key):
    """Method to merge the data in two python dictionaries together """
    dict_data_combo = dict_data_alpha.copy()
    for alpha in dict_data_combo:
        for beta in dict_data_beta:
            if alpha[primary_key] == beta[primary_key]:
                alpha.update(beta)

    return dict_data_combo


################################ Edit Dictionaries #######################################


def filter_loc(loc_data, loc_keys):
    """Method to filter out redundant values from our location data"""
    clean_data = []
    for old_dict in loc_data:
        filtered_dict = {a_key: old_dict[a_key] for a_key in loc_keys}
        clean_data.append(filtered_dict)
    return clean_data


def filter_data(list_of_dicts):
    """Method to filter out unwanted data from a list of python dictionaries based on keys """
    all_keys = get_all_keys(list_of_dicts)
    not_done = True

    while not_done:
        print("\n[>] Valid Column Names:")
        print("[{}]".format(", ".join(all_keys)))
        print(
            "\n[+] Please enter all the Columns from the above list (separated by a ',') to remove"
        )
        keys_string = input("\t[->]: ")
        rem_keys = keys_string.split(",")
        rem_keys = [key.strip() for key in rem_keys]
        if set(rem_keys).issubset(all_keys):
            print(
                "\n[+] Removing the following Columns: [{}]".format(", ".join(rem_keys))
            )
            not_done = False
            # Cycle through the list of dictionaries and filter out provided keys
            for target_dict in list_of_dicts:
                target_dict = delete_items(target_dict, rem_keys)
        else:
            if keys_string.lower() == "quit":
                print("\n[*] Exiting with out editing results...\n")
                not_done = False
            else:
                print(
                    "\n[!] ERROR -> One of the following keys is not valid... \n\t[{}]".format(
                        ", ".join(rem_keys)
                    )
                )
                print(
                    "\n[-] Please try again or type 'QUIT' to exit with out editing results.\n"
                )
                # sys.exit(1)

    return list_of_dicts


def delete_items(target_dict, rem_keys):
    """Method to check if a list keys to be removed are in a dictionary before deleting them"""
    primary_key = "source_ip"
    for key in rem_keys:
        if key in target_dict:
            if key == primary_key:
                print(
                    "\n[!]Error -> Sorry Primary Key: '{}' is essential data".format(
                        primary_key
                    )
                )
            else:
                # Delete key from dictionary via pop()
                target_dict.pop(key)
    return target_dict


def select_data(list_of_dicts):
    """Method to select specific data from a list of python dictionaries from a list of all keys """
    all_keys = get_all_keys(list_of_dicts)
    not_done = True
    while not_done:
        print("\n[>] Valid Column Names:")
        print("[{}]".format(", ".join(all_keys)))
        print(
            "\n[+] Please enter all the Columns from the above list (separated by a ',') to keep"
        )
        print("[+] Note: to exit this section without editing the data, please type: 'quit'")
        keys_string = input("\t[->]: ")
        sel_keys = keys_string.split(",")
        sel_keys = [key.strip() for key in sel_keys]
        sel_keys = [key.replace(" ", "") for key in sel_keys]
        if set(sel_keys).issubset(all_keys):
            print("\n[+] Saving only the following Columns: [{}]".format(", ".join(sel_keys)))
            # Grab keys from all_keys that are NOT the ones the user wants to save (i.e. sel_keys)
            # These keys represent unwanted data - which will be deleted to save space
            rem_keys = [key for key in all_keys if key not in sel_keys]
            not_done = False
            # Cycle through the list of dictionaries and filter out provided keys
            for target_dict in list_of_dicts:
                target_dict = delete_items(target_dict, rem_keys)
        else:
            if keys_string.lower() == "quit":
                print("\n[*] Exiting with out editing results...\n")
                not_done = False
            else:
                print(
                    "\n[!] ERROR -> One of the following keys is not valid... \n\t[{}]".format(
                        ", ".join(sel_keys)
                    )
                )
                print(
                    "\n[-] Please try again or type 'QUIT' to exit with out editing results.\n"
                )
                # sys.exit(1)

    return list_of_dicts


def get_all_keys(list_of_dicts):
    """ Get all the Keys from an uneven list of python dictionaries """
    fieldnames = set()
    primary_key = "source_ip"
    for current_dict in list_of_dicts:
        fieldnames.update(current_dict.keys())
    fieldnames = sorted(fieldnames)
    # Since keys are now sorted, remove and add primary key to front of list
    fieldnames.remove(primary_key)
    fieldnames[:0] = [primary_key]
    return fieldnames


def edit_results(final_results, primary_key):
    """Method to ask if the user wants to edit the retrieved data from the search results"""
    not_done = True
    # Create a copy.deepcopy() of the results, so that any edits to data can be easily undone
    filtered_results = copy.deepcopy(final_results)
    while not_done:
        if ask_question(
            "Would you like to edit/view the results before saving?", not_done
        ):
            if ask_custom_question(
                "Please choose to either Select or Remove data", "Select", "Remove", not_done
            ):
                filtered_results = select_data(filtered_results)
            else:
                filtered_results = filter_data(filtered_results)
            if ask_question("Would you like to view the results?", not_done):
                display_list_of_dicts(filtered_results, primary_key)
            else:
                not_done = False
            if ask_question(
                "Would you like to store these new results instead of originals?", True
            ):
                # Replace original results with edited results
                final_results = filtered_results
                not_done = False
        else:
            not_done = False

    print("\nFINAL:\n{} \n\nFILTERED\n{}".format(final_results, filtered_results))
    return final_results


################################# List Comparison ########################################


def get_matches(known_values, new_values):
    """ Compare two lists, counts and returns the elements matching provided known values """
    matched_elements = []
    match_count = 0

    print("\n[*] Checking for matches to provided list of known values")
    #  TO DO
    for k_value in known_values:
        for n_item in new_values:
            if n_item == k_value:
                matched_elements.append(n_item)
                match_count += 1

    print("[+] All elements checked and {} matches found.\n".format(match_count))
    return matched_elements


def get_unique_values(known_values, new_values):
    """ Compare two lists, counts and returns unique elements not found in known values """
    unique_values = []
    # Note: new_list = list[:] signals that we want a copy of the original list,
    #       otherwise using new_list.remove() lower down would alter both lists
    unique_values = new_values[:]
    unique_count = 0

    for k_value in known_values:
        for current_item in unique_values:

            if current_item == k_value:
                unique_values.remove(current_item)
                unique_count += 1

    return unique_values


def compare_lists(known_values, new_values):
    """ Compare two lists and return sets of both unique and matching elements values """

    matching_values = get_matches(known_values, new_values)
    unique_values = get_unique_values(matching_values, new_values)

    return matching_values, unique_values


################################## Display Data #########################################


def display_dict(dict_data):
    """Method to display the contents of a dictionary"""
    for key, value in dict_data.items():
        print(f"\t{key}:\t\t{value}")


def display_list_of_dicts(list_of_dicts, primary_key):
    """Method to cycle through a list of dictionaries and display contents"""
    for dict_data in list_of_dicts:
        print(f"\n****** {dict_data[primary_key]} *******\n")
        display_dict(dict_data)


def process_single_ip(
    single_ip, tor_check, host_lookup, locate_ip, who_is, tor_exit_nodes
):
    """Method to process a single IP address and display results"""
    print(f"\n[*] Processing IP : '{single_ip}'\n")

    if tor_check:
        tor_dict = check_tor(single_ip, tor_exit_nodes)
        print(f"[+] TOR Data IP: '{single_ip}'")
        display_dict(tor_dict)
        if tor_dict["is_TOR"]:
            print(f"\tTarget: '{single_ip}', matches a known TOR Exit Node")
        else:
            print(f"\tTarget: '{single_ip}', does not seem to be a known TOR Exit Node")
        print("\t*** *** *** *** *** ***\n")

    if host_lookup:
        host_data = get_host_data(single_ip)
        print(f"[+] Host Data: '{single_ip}'")
        display_dict(host_data)
        print("\t*** *** *** *** *** ***\n")

    if locate_ip:
        loc_data = get_location_data(single_ip)
        print(f"[+] Location Data: '{single_ip}'")
        display_dict(loc_data)
        print("\t*** *** *** *** *** ***\n")

    if who_is:
        text_results = perform_whois(single_ip)
        whois_data = create_dict(text_results, single_ip)
        print(f"[+] WHOIS Data: '{single_ip}'")
        display_dict(whois_data)
        print("\t*** *** *** *** *** ***\n")


################################# Ask  User ########################################


def ask_question(question, not_done):
    """Method to ask the user a simple yes or no question"""

    while not_done:
        answer = input("\n[?] {} ['yes' or 'no']: ".format(question))

        if answer[0].lower() == "y":
            break
        if answer[0].lower() == "n":
            not_done = False
            break

        print("\n[!] ERROR - your response", answer, " is invalid!\n")
        print('[-] Please type either "Yes" or "No"!\n')

    return not_done


def ask_custom_question(question, choice_one, choice_two, not_done):
    """Method to ask the user a customized True or False question"""

    while not_done:
        answer = input(
            "\n[?] {} ['{}' or '{}']: ".format(question, choice_one, choice_two)
        )

        if answer[0].lower() == choice_one[0].lower():
            break
        if answer[0].lower() == choice_two[0].lower():
            not_done = False
            break

        print("\n[!] ERROR - your response", answer, " is invalid!\n")
        print("[-] Please type either '{}' or '{}'!\n".format(choice_one, choice_two))

    return not_done


################################# File Processing ########################################


def read_in_nline(file_name):
    """ Read in data from a file, splitting it up line by line """
    with open(file_name, "r") as in_file:
        data = in_file.read().splitlines()
    return data


def write_to_csvfile(dict_data, field_names, dir_out, out_file):
    """Method to export the data in a list of Python Dictionaries to a CSV file"""
    csv_columns = field_names

    dir_name = dir_out
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

    try:
        with open(os.path.join(dir_name, out_file), "w") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()
            for data in dict_data:
                writer.writerow(data)
    except IOError:
        print("\n[!] WARNING --> I/O Error!")


def write_to_jsonfile(dict_data, dir_out, out_file):
    """Method to export a list of Python Dictionaries to a JSON file"""

    dir_name = dir_out
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

    try:
        with open(os.path.join(dir_name, out_file), "w") as json_file:
            json.dump(dict_data, json_file)
    except IOError:
        print("\n[!] WARNING --> I/O Error!")


def save_or_edit(final_results, primary_key, export_type, dir_out, output_file):
    """Method to determine if the user wants to edit data before saving"""
    # Check to see if the user wants to filter out any unwanted/missing data
    final_results = edit_results(final_results, primary_key)

    if output_file:
        out_file = output_file
    else:
        out_file = input(
            "\n[->] Please enter the file name where you wish to store the results: "
        )
    # Save the results to the specified file type
    if ask_question("Would you like to view the final results before saving?", True):
        display_list_of_dicts(final_results, primary_key)
    export_data(export_type, final_results, dir_out, out_file)

def save_data(final_results, export_type, dir_out, output_file):
    """Method to save results and check that an output file name has been provided"""

    if output_file:
        out_file = output_file
    else:
        out_file = input(
            "\n[->] Please enter the file name where you wish to store the results: "
        )
    # Save the results to the specified file type
    export_data(export_type, final_results, dir_out, out_file)


def export_data(export_type, dict_data, dir_out, file_name):
    """Method to determine which format the user selected to export data as"""
    if export_type == "CSV":
        out_file = file_name.rsplit(".", 1)[0] + ".csv"
        print("\n[+] Exporting data to: {}/{}".format(dir_out, out_file))
        all_keys = get_all_keys(dict_data)
        write_to_csvfile(dict_data, all_keys, dir_out, out_file)
    elif export_type == "JSON":
        out_file = file_name.rsplit(".", 1)[0] + ".json"
        print("\n[+] Exporting data to: {}/{}".format(dir_out, out_file))
        write_to_jsonfile(dict_data, dir_out, out_file)
    else:
        print("\n[!] ERROR -> Export Type: '{}' is NOT valid!".format(export_type))
        print("[-] File(s) FAILED to export...")


################################# Main() Method #########################################
def main():
    """Main() Method"""

    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Last Modified by {} on {}".format(", ".join(__author__), __date__),
    )
    parser.add_argument(
        "-i",
        "--ip_address",
        nargs="?",
        dest="ip_address",
        help="Input a single IP address that you wish to collect information on",
    )
    parser.add_argument(
        "-m",
        "--multiple_ips",
        nargs="*",
        dest="multiple_ips",
        help="Input multiple IP addresses from the command line to investigate",
    )
    parser.add_argument(
        "-f",
        "--file_name",
        nargs="?",
        dest="file_name",
        help="Input the file name that contains a list of IP addresses to investigate",
    )
    parser.add_argument(
        "-t",
        "--tor_nodes",
        nargs="?",
        dest="tor_nodes",
        default=None,
        help="Input file name that contains the known TOR exit nodes for local check",
    )
    parser.add_argument(
        "-o",
        "--output_file",
        nargs="?",
        dest="output_file",
        default="IP_Lookup_Results",
        help="Output file name where you want to save any results from the investigation",
    )
    parser.add_argument(
        "-d",
        "--directory_out",
        nargs="?",
        dest="dir_out",
        default="IP_Data",
        help="Set the name of the Directory to save the data collected on the IP addresses",
    )
    parser.add_argument(
        "-e",
        "--export_type",
        nargs="?",
        dest="export_type",
        choices=["CSV", "JSON"],
        default="JSON",
        help="Select the type of file format you wish to export data to (default=JSON)",
    )
    parser.add_argument(
        "-W",
        "--who_is",
        dest="who_is",
        action="store_true",
        help="Signal that you want to perform a full WHOIS record lookup on provided IPs",
    )
    parser.add_argument(
        "-H",
        "--host_lookup",
        dest="host_lookup",
        action="store_true",
        help="Signal that you want to perform a host lookup by IP address on the targets",
    )
    parser.add_argument(
        "-L",
        "--locate_ip",
        dest="locate_ip",
        action="store_true",
        help="Signal that you want to retreive location data relating to the target IPs",
    )
    parser.add_argument(
        "-T",
        "--tor_check",
        dest="tor_check",
        action="store_true",
        help="Signal that you want to check target IP(s) against known TOR exit nodes",
    )
    parser.add_argument(
        "-A",
        "--alter_results",
        dest="alter_results",
        action="store_true",
        help="Signal that you wish to alter the results retrieved by filtering out some data",
    )
    parser.add_argument(
        "-S",
        "--save_results",
        dest="save_results",
        action="store_true",
        help="Signal that you wish to save the results from this program to some file",
    )

    # Check for above arguments - if none are provided, Display --help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    print("\n*** *** ***  Running '{}'  *** *** ***".format(sys.argv[0]))

    who_is = args.who_is
    host_lookup = args.host_lookup
    locate_ip = args.locate_ip
    tor_check = args.tor_check

    save_results = args.save_results
    export_type = args.export_type
    dir_out = args.dir_out

    primary_key = "source_ip"

    # Check if investigating a single IP address or many
    if args.ip_address:
        single_ip = args.ip_address

    elif args.multiple_ips:
        susp_ips = args.multiple_ips

    elif args.file_name:
        input_file = args.file_name
        if os.path.isfile(input_file):
            susp_ips = read_in_nline(input_file)
        else:
            print("[!] ERROR ->'{}' is NOT a valid file.".format(input_file))
            sys.exit(1)
    else:
        user_input = input(
            "\n[->] Please enter a valid IPv4 address that you wish to investigate: "
        )
        if validate_ip(user_input):
            single_ip = user_input
        else:
            print("[!] ERROR ->'{}' is NOT a valid IP address.".format(user_input))
            sys.exit(1)

    if tor_check:
        if args.tor_nodes:
            tor_nodes = args.tor_nodes
            # Check that the provided file path actually exists
            check_path(tor_nodes)
            tor_exit_nodes = read_in_nline(tor_nodes)
        else:
            print(
                "\n[!] Location of known TOR exit nodes file is currently not specified..."
            )
            print(
                "\tNote: Data should be availble here: https://check.torproject.org/torbulkexitlist"
            )
            tor_nodes = input(
                "[->] Please enter the file path to known TOR exit nodes: "
            )
            check_path(tor_nodes)
            tor_exit_nodes = read_in_nline(tor_nodes)
    else:
        tor_exit_nodes = None

    if args.ip_address:
        process_single_ip(
            single_ip, tor_check, host_lookup, locate_ip, who_is, tor_exit_nodes
        )
    else:
        if host_lookup:
            host_results = []
        if locate_ip:
            loc_results = []
        if who_is:
            whois_results = []
        if tor_check:
            tor_results = []

        for target_ip in susp_ips:
            print(f"\n[+] Processing IP : '{target_ip}'")

            if tor_check:
                tor_dict = check_tor(target_ip, tor_exit_nodes)
                tor_results.append(tor_dict)

            if host_lookup:
                host_dict = get_host_data(target_ip)
                host_results.append(host_dict)

            if locate_ip:
                loc_dict = get_location_data(target_ip)
                loc_results.append(loc_dict)

            if who_is:
                text_results = perform_whois(target_ip)
                whois_dict = create_dict(text_results, target_ip)
                whois_results.append(whois_dict)

        if save_results:
            # Merge all results - not the most elegant solution, I know, but it currently works
            if tor_check:
                if host_lookup:
                    final_results = merge_data(tor_results, host_results, primary_key)
                    if locate_ip:
                        final_results = merge_data(
                            final_results, loc_results, primary_key
                        )
                        if who_is:
                            final_results = merge_data(
                                final_results, whois_results, primary_key
                            )
                    elif who_is:
                        final_results = merge_data(
                            tor_results, whois_results, primary_key
                        )
                elif locate_ip:
                    final_results = merge_data(tor_results, loc_results, primary_key)
                    if who_is:
                        final_results = merge_data(
                            final_results, whois_results, primary_key
                        )
                elif who_is:
                    final_results = merge_data(tor_results, whois_results, primary_key)
                else:
                    final_results = tor_results

            elif host_lookup:
                if locate_ip:
                    final_results = merge_data(host_results, loc_results, primary_key)
                    if who_is:
                        final_results = merge_data(
                            final_results, whois_results, primary_key
                        )
                elif who_is:
                    final_results = merge_data(host_results, whois_results, primary_key)
                else:
                    final_results = host_results

            elif locate_ip:
                if who_is:
                    final_results = merge_data(loc_results, whois_results, primary_key)
                else:
                    final_results = loc_results

            else:
                if who_is:
                    final_results = whois_results
                else:
                    print("\n[!] ERROR -> No Results found to save...")
                    sys.exit(1)

            # Check if user wants to edit results and then save file
            if args.alter_results:
                save_or_edit(
                    final_results, primary_key, export_type, dir_out, args.output_file
                )
            else:
                save_data(final_results, export_type, dir_out, args.output_file)

        else:

            print("\n\t*** *** ****** *** ***")
            print("\n\t\tRESULTS")
            print("\n\t*** *** ****** *** ***")

            if tor_check:
                display_list_of_dicts(tor_results, primary_key)

            if host_lookup:
                display_list_of_dicts(host_results, primary_key)

            if locate_ip:
                display_list_of_dicts(loc_results, primary_key)

            if who_is:
                display_list_of_dicts(whois_results, primary_key)

    print("\n*** *** *** *** *** *** *** *** ***\n")


##########################################################################################

if __name__ == "__main__":

    main()
