import load_data
import pandas


def print_number_of_each_category():
    print("Loading the data for each year")
    data_2018: pandas.DataFrame = load_data.get_2018_data()
    data_2019: pandas.DataFrame = load_data.get_2019_data()
    data_2020: pandas.DataFrame = load_data.get_2020_data()
    data_2021: pandas.DataFrame = load_data.get_2021_data()
    data_years = [data_2018, data_2019, data_2020, data_2021]
    year = 2018
    print("Data loaded successfully")

    for data_year in data_years:
        print("analyzing the data for the year " + str(year))
        size = len(data_year.index)
        buffer_overflow = []
        integer_overflow = []
        format_string = []
        php_remote_file_inclusion = []
        sql_injection = []
        authentication = []
        directory_traversal = []
        denial_of_service = []
        privilege_action = []
        cross_site_request_forgery = []
        crlf_injection = []
        race_condition = []
        cryptographic_error = []
        information_leak_disclosure = []
        cross_site_scripting = []
        use_after_free = []
        server_side_request_forgery = []
        improper_input_validation = []
        os_command_injection = []
        unrestricted_file_upload = []
        critical_function_auth_missing = []
        hard_coded_credentials = []
        missing_authorization = []
        incorrect_default_permissions = []
        for i in range(0, size):
            data_point = data_year.iloc[i]
            # Useful in debugging
            # description = str(data_point["CVE_Items"]["cve"]["description"]["description_data"][0]["value"]).lower()
            problem_type_data = data_point["CVE_Items"]["cve"]["problemtype"]["problemtype_data"]
            if len(problem_type_data) > 1:
                print("CVE has more than 1 problem data")
            for problem_type in problem_type_data[0]["description"]:
                category = problem_type["value"]
                if category == "CWE-121" or category == "CWE-122" or category == "CWE-680" or category == "CWE-125" or \
                        category == "CWE-787" or category == "CWE-119" or category == "CWE-120" or \
                        category == "CWE-131":
                    buffer_overflow.append(data_point)
                if category == "CWE-190" or category == "CWE-680":
                    integer_overflow.append(data_point)
                if category == "CWE-134":
                    format_string.append(data_point)
                if category == "CWE-98":
                    php_remote_file_inclusion.append(data_point)
                if category == "CWE-89" or category == "CWE-564":
                    sql_injection.append(data_point)
                if category == "CWE-287" or category == "CWE-1390" or category == "CWE-287":
                    authentication.append(data_point)
                if category == "CWE-23" or category == "CWE-35" or category == "CWE-22" or category == "CWE-73":
                    directory_traversal.append(data_point)
                if category == "CWE-711" or category == "CWE-248" or category == "CWE-369" or category == "CWE-382" or \
                        category == "CWE-400" or category == "CWE-401" or category == "CWE-404" or \
                        category == "CWE-405" or category == "CWE-410" or category == "CWE-412" or \
                        category == "CWE-170" or category == "CWE-476" or category == "CWE-674":
                    denial_of_service.append(data_point)
                if category == "CWE-269" or category == "CWE-250" or category == "CWE-264" or category == "CWE-267":
                    privilege_action.append(data_point)
                if category == "CWE-352":
                    cross_site_request_forgery.append(data_point)
                if category == "CWE-93" or category == "CWE-113":
                    crlf_injection.append(data_point)
                if category == "CWE-362" or category == "CWE-367" or category == "CWE-366" or category == "CWE-364" or \
                        category == "CWE-421":
                    race_condition.append(data_point)
                if category == "CWE-310" or category == "CWE-320" or category == "CWE-330" or category == "CWE-326":
                    cryptographic_error.append(data_point)
                if category == "CWE-200" or category == "CWE-209" or category == "CWE-497" or category == "CWE-526" or \
                        category == "CWE-532" or category == "CWE-535":
                    information_leak_disclosure.append(data_point)
                if category == "CWE-79":
                    cross_site_scripting.append(data_point)
                if category == "CWE-416":
                    use_after_free.append(data_point)
                if category == "CWE-918":
                    server_side_request_forgery.append(data_point)
                if category == "CWE-20":
                    improper_input_validation.append(data_point)
                if category == "CWE-78":
                    os_command_injection.append(data_point)
                if category == "CWE-434":
                    unrestricted_file_upload.append(data_point)
                if category == "CWE-306":
                    critical_function_auth_missing.append(data_point)
                if category == "CWE-798":
                    hard_coded_credentials.append(data_point)
                if category == "CWE-862":
                    missing_authorization.append(data_point)
                if category == "CWE-276":
                    incorrect_default_permissions.append(data_point)

        average_cvss_2_score = get_average_cvss_2_score(buffer_overflow)
        print("there were " + str(len(buffer_overflow)) + " buffer overflow CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))

        average_cvss_2_score = get_average_cvss_2_score(integer_overflow)
        print("there were " + str(len(integer_overflow)) + " integer overflow CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(format_string)
        print("there were " + str(len(format_string)) + " String formatting CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(php_remote_file_inclusion)
        print("there were " + str(len(php_remote_file_inclusion)) + " PHP remote file inclusion CVE's in " +
              str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(sql_injection)
        print("there were " + str(len(sql_injection)) + " SQL injection CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(authentication)
        print("there were " + str(len(authentication)) + " authentication CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(directory_traversal)
        print("there were " + str(len(directory_traversal)) + " directory traversal CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(denial_of_service)
        print("there were " + str(len(denial_of_service)) + " denial of service CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(privilege_action)
        print("there were " + str(len(privilege_action)) + " privilege action CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(cross_site_request_forgery)
        print("there were " + str(len(cross_site_request_forgery)) + " CSRF CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(crlf_injection)
        print("there were " + str(len(crlf_injection)) + " CRLF CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(race_condition)
        print("there were " + str(len(race_condition)) + " race condition CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(race_condition)
        print("there were " + str(len(cryptographic_error)) + " cryptographic error CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(information_leak_disclosure)
        print("there were " + str(len(information_leak_disclosure)) + " information disclosure CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        
        print("\n\n\n")

        print("that concludes the original work in the paper we are referencing")
        print("here starts the categories that we have added, to add complexity")
        print("\n\n\n")

        average_cvss_2_score = get_average_cvss_2_score(use_after_free)
        print("there were " + str(len(use_after_free)) + " use after free CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(server_side_request_forgery)
        print("there were " + str(len(server_side_request_forgery)) + " server side request forgery CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(improper_input_validation)
        print("there were " + str(len(improper_input_validation)) + " improper input validation CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(os_command_injection)
        print("there were " + str(len(os_command_injection)) + " os command injection CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(unrestricted_file_upload)
        print("there were " + str(len(unrestricted_file_upload)) + " unrestricted file upload CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(critical_function_auth_missing)
        print("there were " + str(len(critical_function_auth_missing)) + " missing authentication for critical function CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(hard_coded_credentials)
        print("there were " + str(len(hard_coded_credentials)) + " use of hard coded credentials CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(missing_authorization)
        print("there were " + str(len(missing_authorization)) + " missing authorization CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))
        average_cvss_2_score = get_average_cvss_2_score(incorrect_default_permissions)
        print("there were " + str(len(incorrect_default_permissions)) + " incorrect default permissions CVE's in " + str(year)
              + " with an average CVSS2 score of " + str(average_cvss_2_score))

        print("\n\n\n")
        year += 1


def get_average_cvss_2_score(vuln_list):
    if len(vuln_list) == 0:
        return 0.0
    average_cvss_2_score = 0.0
    for vuln in vuln_list:
        average_cvss_2_score += vuln["CVE_Items"]["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
    average_cvss_2_score = average_cvss_2_score / len(vuln_list)
    return str(round(average_cvss_2_score, 2))


if __name__ == '__main__':
    print_number_of_each_category()
