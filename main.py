import pandas

import load_data
import pandas as pd


def main():
    print("Loading the data files ...")
    data = load_data.get_data()
    print("Data loaded successfully!")
    print_basic_analytics(data)


def print_basic_analytics(data: pandas.DataFrame):
    average_cve_severity = 0
    size = len(data.index)
    valid_data_points = size
    print("Number of data points: " + str(size))
    for i in range(0, size):
        d1 = data.iloc[i]["CVE_Items"]["impact"]
        if d1 == {}:
            valid_data_points -= 1
            continue
        try:
            score = d1["baseMetricV3"]["cvssV3"]["baseScore"]
        except KeyError:
            print(str(d1))
            continue
        average_cve_severity += score

    average_cve_severity = average_cve_severity / valid_data_points
    print("Number of valid data points: " + str(valid_data_points))
    print("average CVE severity: " + str(average_cve_severity))


if __name__ == '__main__':
    main()
