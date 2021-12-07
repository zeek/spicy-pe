# @TEST-EXEC: zeek -r ${TRACES}/ftp-pe.pcap %INPUT
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff pe.log
#
# @TEST-DOC: Test PE analyzer with an executable transferred over FTP, with the logging of the enrire import table enabled


@load analyzer

redef PE::pe_log_import_table = T;
