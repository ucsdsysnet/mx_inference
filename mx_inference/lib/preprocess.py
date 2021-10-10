from collections import defaultdict
from mx_inference.lib.extract_domain import registered_domain_of_fqdn
from mx_inference.lib.union_find import uf_connect, uf_parent

# Preprocess certs
def preprocess_get_basic_stats(domain_objs):
    cnt_cert_fqdn = defaultdict(int)
    cnt_cert_rd = defaultdict(int)
    cnt_ip = defaultdict(int)
    cnt_mx = defaultdict(int)
    for domain_obj in domain_objs:
        set_cert_fqdn = set()
        set_cert_rd = set()
        set_ip = set()
        set_mx = set()

        preferred_mx_records_of_a_domain = domain_obj.get_most_preferred_mx_records_with_smtp()
        for mx in preferred_mx_records_of_a_domain:
            set_mx.add(mx.get_mx_str())
            for ip in mx.get_ips():
                set_ip.add(ip.get_ip_str())
                for fqdn in ip.get_valid_cert_fqdns():
                    set_cert_fqdn.add(fqdn)
                    set_cert_rd.add(registered_domain_of_fqdn(fqdn))
        
        for fqdn in set_cert_fqdn:
            cnt_cert_fqdn[fqdn] += 1
        for rd in set_cert_rd:
            cnt_cert_rd[rd] += 1
        for ip in set_ip:
            cnt_ip[ip] += 1
        for mx in set_mx:
            cnt_mx[mx] += 1
    
    return dict(cnt_mx),dict(cnt_ip),dict(cnt_cert_rd),dict(cnt_cert_fqdn)
        
        
# Group certs and produce a name
def preprocess_group_certs(domain_objs,cnt_cert_rd,cnt_cert_fqdn):
    # used in union-find algo
    parent = defaultdict(lambda: None)
    cert_fqdn_to_group_name = {}

    for domain_obj in domain_objs:
        preferred_mx_records_of_a_domain = domain_obj.get_most_preferred_mx_records_with_smtp()
        for mx in preferred_mx_records_of_a_domain:
            for ip in mx.get_ips():
                fqdns = ip.get_valid_cert_fqdns()
                if len(fqdns) == 0:
                    continue
                if len(fqdns) == 1:
                    _ = uf_parent(fqdns[0], parent)
                for x,y in zip(fqdns[:-1],fqdns[1:]):
                    x_parent = uf_parent(x,parent)
                    y_parent = uf_parent(y,parent)
                    x_parent_rd = registered_domain_of_fqdn(x_parent)
                    y_parent_rd = registered_domain_of_fqdn(y_parent)
                    # two nodes in same set, skip
                    if x_parent == y_parent:
                        pass
                    else:
                        # if both parents are equally popular
                        if cnt_cert_rd[x_parent_rd] == cnt_cert_rd[y_parent_rd]:
                            if x_parent < y_parent:
                                uf_connect(x_parent,y_parent,parent)
                            else:
                                uf_connect(y_parent,x_parent,parent)
                        # else maximize popular rds, capture all false positives
                        elif cnt_cert_rd[x_parent_rd] > cnt_cert_rd[y_parent_rd]:
                            uf_connect(x_parent,y_parent,parent)
                        else:
                            uf_connect(y_parent,x_parent,parent) 

    for i in parent.keys():
        i_parent = uf_parent(i,parent)
        cert_fqdn_to_group_name[i] = registered_domain_of_fqdn(i_parent)

    return cert_fqdn_to_group_name

