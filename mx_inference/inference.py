import mx_inference.lib.inference_funcs as funcs
from mx_inference.lib.preprocess import preprocess_group_certs, preprocess_get_basic_stats
from mx_inference.lib.heuristics import Heuristics
from mx_inference.config.config import CONFIG


class MXInference():
    def __init__(self):
        try:
            names_of_infer_funcs = CONFIG['INFERENCE_FUNCTIONS']
            self.infer_funcs = [getattr(funcs,name).infer for name in names_of_infer_funcs]
        except Exception as e:
            raise Exception("Failed to initialize inference functions, error msg: {}".format(e))

    # Infer id of an domain. Input: domain_obj that contains relevant information of a domain
    def infer_id(self,domain_obj):
        return self.infer_ids([domain_obj])[0]
    
    # Infer id of multiple domains. Input: domain_objs that contain relevant information of domains
    def infer_ids(self,domain_objs):
        # Save all stats 
        stats = {}

        # Go through preprocessing
        cnt_mx,cnt_ip,cnt_cert_rd,cnt_cert_fqdn = preprocess_get_basic_stats(domain_objs)
        stats['cnt_mx'] = cnt_mx
        stats['cnt_ip'] = cnt_ip
        stats['cnt_cert_rd'] = cnt_cert_rd
        stats['cnt_cert_fqdn'] = cnt_cert_fqdn

        # Run stats on domains
        cert_fqdn_to_group_name = preprocess_group_certs(domain_objs,cnt_cert_rd,cnt_cert_fqdn)
        stats['cert_fqdn_to_group_name'] = cert_fqdn_to_group_name

        # Go through all functions defined in Config one by one
        for domain_obj in domain_objs:
            self._infer_provider_id_for_mx_of_one_domain(domain_obj, stats)
            self._summarize_provider_ids_of_a_domain(domain_obj)
                            
        return domain_objs

    # Compute a provider id for each MX
    def _infer_provider_id_for_mx_of_one_domain(self, domain_obj, stats):
        # For each mx, infer an id
        for mx in domain_obj.get_most_preferred_mx_records_with_smtp():
            for infer_func in self.infer_funcs:
                # Compute provider id with priority
                potential_provider_id = infer_func(mx, stats)
                if "OK" in potential_provider_id.provider_id_type:
                    mx.pid = potential_provider_id

                    # If USE_HEURISTICS
                    if 'USE_HEURISTICS' in CONFIG:
                        Heuristics.run_heuristics(mx)
                    # If map id to company
                    if CONFIG['PROVIDER_ID_TO_COMPANY'] == True:
                        Heuristics.infer_company_of_mx(mx)
                    
                    break

        
    # Extract pid for MX records that are most preferred
    def _summarize_provider_ids_of_a_domain(self, domain_obj):
        for mx in domain_obj.get_most_preferred_mx_records_with_smtp():
            if mx.pid != None:
                domain_obj.add_pid(mx.pid)


