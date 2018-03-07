import sys

sys.path.append("../src/")

from app.pcap_exception import PcapFileNotFoundError
import pyaiengine
import whois


class TopDNSDomainNames(object):
    """
        TopDNSDomainNames : This class is responsible to count top dns domain names,
        and also get the information about when domains had been registered.
        domain date of creation from input (pcap) file.
    """

    def __init__(self, pcap=None):
        """Class constructor initializing the ai engine parameters

        :param pcap: pcap file as input for PacketDispatcher
        :param st: load an instance of a Lan Network Stack
        :param st.udp_flows: allocate the UDP flows in order to keep memory
        :param pcap: input file
        :param domains: holding main domain and sub domain names
        """

        # Load an instance of a Lan Network Stack
        self.st = pyaiengine.StackLan()

        # Allocate the UDP flows in order to keep memory
        # under control and avoid allocations during the execution
        self.st.udp_flows = 163840

        # input pcap file
        self.pcap = pcap
        self.domains = dict()

        print(self.pcap)

    def domain_names(self):
        """Fit the pcap as input file to pyaiengine.PacketDispatcher,
           Gets the total number of packets process by the PacketDispatcher.

                Returns
                -------
                self : dictionary object or raise PcapFileNotFoundError
                    Returns domains.

                if pcap is not None:
                    :return domains
                else:
                    :return raise PcapFileNotFoundError
        """
        try:
            if self.pcap is not None:
                with pyaiengine.PacketDispatcher(self.pcap) as pd:
                    pd.stack = self.st
                    pd.run()

                # Get the UDP flows processed
                self.flows = self.st.udp_flow_manager

                for flow in self.flows:
                    if flow.bytes > 0:
                        if flow.dns_info:
                            name = flow.dns_info.domain_name
                            if not self.domains.has_key(name):
                                self.domains[name] = 1
                            else:
                                self.domains[name] += 1

            raise PcapFileNotFoundError('Pcap file not found : {}'.format(self.pcap))

        except Exception as excep:
            # print('I/O Exception occured: ', error.message)
            pass

        return self.domains

    def flow_manager_statistics(self):
        """Statistical information about number of flows stored on the FlowManager.

            :return flows object
        """
        return self.flows

    def flow_length(self):
        """Gets the number of Flows stored on the FlowManager.

            :return __len__. Gets the number of Flows stored on the FlowManager.
        """
        return len(self.flows)

    def domain_creation(self, domain_keys):
        """Getting domain information concerned with date of creation when domain name was registered.

            Returns
            -------
            self : object
                :return creation_dict

        """
        creation_dict = dict()
        for domain in domain_keys:
            try:
                w = whois.whois(str(domain))
                creation_dict[domain] = w["creation_date"]
            except:
                # w = whois.whois(str(whois.extract_domain(str(domain))))
                # creation_dict[domain] = w["creation_date"]

                creation_dict[domain] = domain + ' Sub Domain'
        return creation_dict
