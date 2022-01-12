# @TEST-EXEC: zeek -r ${TRACES}/http-sample-dll.pcap %INPUT
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff pe.log
#
# @TEST-DOC: Test PE analyzer with an executable transferred over HTTP, with the logging of the entire import & export table enabled


@load analyzer

redef PE::pe_log_import_table = T;
redef PE::pe_log_export_table = T;
