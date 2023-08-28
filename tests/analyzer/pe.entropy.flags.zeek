# @TEST-EXEC: zeek -r ${TRACES}/ftp-pe.pcap %INPUT
# @TEST-EXEC: cat files.log | zeek-cut -C ts analyzers >files2.log && mv files2.log files.log
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: cat pe.log | zeek-cut -nC id > pe2.log && mv pe2.log pe.log
# @TEST-EXEC: btest-diff pe.log
#
# @TEST-DOC: Test PE analyzer with an executable transferred over FTP, with the calculation of the section entropy + logging of section flags enabled

@load analyzer

redef PE::pe_log_section_entropy = T;
redef PE::pe_log_section_flags = T;
