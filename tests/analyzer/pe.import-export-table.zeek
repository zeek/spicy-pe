# @TEST-EXEC: zeek -r ${TRACES}/http-sample-dll.pcap %INPUT
# @TEST-EXEC: cat files.log | zeek-cut -C ts analyzers >files2.log && mv files2.log files.log
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: cat pe.log | zeek-cut -nC id > pe2.log && mv pe2.log pe.log
# @TEST-EXEC: btest-diff pe.log
#
# @TEST-DOC: Test PE analyzer with an executable transferred over HTTP, with the logging of the entire import & export table enabled

@load analyzer

redef PE::pe_log_import_table = T;
redef PE::pe_log_export_table = T;
