import sys
import datetime
from datetime import datetime as dt
from app.dns_creation import TopDNSDomainNames


def get_days_passed(before, after):
    d1 = before.date()
    d2 = after.date()
    return abs(d1 - d2).days


def main():
    """
        Reading pcap files, extracting date of creation
    """

    if len(sys.argv) < 3:
        print('Usage: python dns_analyzer.py anomalous_pcap_file')
        pcap = 'anom.log.pcap'

        print('Now using default files: ' + pcap)
    else:
        pcap = sys.argv[1]

    today = datetime.date.today()
    date_type = dt(year=today.year, month=today.month, day=today.day)
    top = TopDNSDomainNames(pcap)

    domain = top.domain_names()  # domain dictionary
    print('\n')
    start = input('Starting index value  : ')
    stop = input('Ending index value : ')

    domain_date = top.domain_creation(domain.keys()[start:stop])
    print('\n')

    for domain_name, domain_creation in domain_date.iteritems():
        if type(domain_creation) is list:
            number_of_days = get_days_passed(date_type, domain_creation[0])

            if number_of_days >= 30:
                print('{0} is {1} days old'.format(domain_name, number_of_days))
            else:
                print('{0} is {1} days old'.format(domain_name, number_of_days))

        elif type(domain_creation) is type(date_type):
            number_of_days = get_days_passed(date_type, domain_creation)

            if number_of_days >= 30:
                print('{0} is {1} days old'.format(domain_name, number_of_days))
            else:
                print('{0} is {1} days old'.format(domain_name, number_of_days))

        elif type(domain_creation) is str:
            print("Suspect or Sub domain : {0} ".format(domain_name))

        else:
            print("Suspect or Sub domain : {0} ".format(domain_name))


if __name__ == '__main__':
    main()
