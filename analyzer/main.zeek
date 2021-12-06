module PE;

export {
	option pe_log_section_entropy = F;
	option pe_log_section_flags = F;
	option pe_log_import_table = F;

	# Used to store information per section, non-printable
	type SectionInfo: record{
		entropy: double &optional &default=0.0;
		flags: string &optional &default="";
	}; 

    redef record PE::Info += {
		section_info_table: table[string] of SectionInfo &default=table();
		section_names: vector of string &log &optional;
		import_table: vector of string &log &optional;
		};

	type ExportName: record {
		rva:  count;
		name: string &optional;
	};

	type ExportAddress: record {
		rva:       count;
		forwarder: string &optional;
	};

	type ExportTable: record {
		flags:               count;
		timestamp:           time;
		major_version:       count;
		minor_version:       count;
		dll_name_rva:        count;
		ordinal_base:        count;
		address_table_count: count;
		name_table_count:    count;
		address_table_rva:   count;
		name_table_rva:      count;
		ordinal_table_rva:   count;
		dll:                 string &optional;
		addresses:           vector of ExportAddress &optional;
		names:               vector of ExportName &optional;
		ordinals:            vector of count &optional;
	};

	type Import: record {
		hint_name_rva: count &optional;
		hint:          count &optional;
		name:          string &optional;
		ordinal:       count &optional;
	};

	type ImportTableEntry: record {
		import_lookup_table_rva:  count;
		timestamp:                time;
		forwarder_chain:          count;
		dll_rva:                  count;
		import_address_table_rva: count;
		dll:                      string &optional;
		imports:                  vector of Import &optional;
	};

	type ImportTable: record {
		entries: vector of ImportTableEntry;
	};
}

function shannon_entropy(counts: table[count] of count, sectionTotalBytes: double) : double {
	local entropy: double = 0.0;

	# Calculate the Shannon entropy of the bits
	# https://en.wikipedia.org/wiki/Entropy_(information_theory)
	# H(X) = -sum(P_xi * log_2(xi))
	# where log2() is represented with log10(p_x)/log10(2)
	for (byte, cnt in counts) {
		local p_x: double = cnt/sectionTotalBytes;

		if (p_x > 0.0) {
			entropy = entropy - (p_x * log10(p_x)/log10(2));
		}
	}

	return entropy;
}

event pe_section_bytes_counts(f: fa_file, cts: table[string] of table[count] of count, section_lenghts: table[string] of double) {
	# Ignore this event when we're not interested in the section entropy
	if ( ! pe_log_section_entropy ) {
		return;
	}

	for (section, counts in cts) {
		# Calculate the entropy
		local entropy: double = shannon_entropy(counts, section_lenghts[section]);

		if ( section !in f$pe$section_info_table ) {
			f$pe$section_info_table[section] = [];
		}
		f$pe$section_info_table[section]$entropy = entropy;
	}
}

event pe_section_header(f: fa_file, h: PE::SectionHeader) &priority=1
{
	if ( ! pe_log_section_flags ) {
		return;
	}
	
    # The string that holds the one-character flags, "r", "w" and "e"
    local flag_string: string = "";

    # Only iterate over the chars once and check if some flags are set
    # IMAGE_SCN_MEM_EXECUTE     = 0x20000000 -> The section can be executed as code.
    # IMAGE_SCN_MEM_READ        = 0x40000000 -> The section can be read.
    # IMAGE_SCN_MEM_WRITE       = 0x80000000 -> The section can be written to.

    # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    for ( flag in h$characteristics ) {
        if ( flag == 0x40000000 ) {
            flag_string += "r";
        }
        if ( flag == 0x80000000 ) {
            flag_string += "w";
        }
        if ( flag == 0x20000000 ) {
            flag_string += "e";
        }
    }

	if ( h$name !in f$pe$section_info_table ) {
		f$pe$section_info_table[h$name] = [];
	}
	f$pe$section_info_table[h$name]$flags = flag_string;

}

event pe_import_table(f: fa_file, it: PE::ImportTable) {
	if ( ! pe_log_import_table ) {
		return;
	}
    # The vector that we're going to fill
    local temp_tbl:  vector of string;

    # Iterate over the import table entries
    for ( i in it$entries ) {

        local e = it$entries[i];

        # If there are any imports....
        if ( e?$imports ) {

            # ... iterate over them
            for ( j in e$imports ) {

                # And for every imported function, check whether it's imported by name or ordinal
                # Add the corresponding information to the vector of strings
                local imp = e$imports[j];

                if ( imp?$hint_name_rva ) {
                    temp_tbl += fmt("%s:%s", e?$dll ? e$dll : "nil", imp?$name ? imp$name : "<nil>");
                }
                else {
                    temp_tbl += fmt("%s:%s", e?$dll ? e$dll : "nil", imp$ordinal);
                }
            }
        }
    }
    # Finally, put it in the actual PE log
    f$pe$import_table = temp_tbl;
}

# Called when the file analysis is closed
event file_state_remove(f: fa_file)
    {
	# If any of the new logging is enabled, delete the default section_names field
	# This means that default functionality is not changed
	if ( pe_log_section_flags  || pe_log_section_entropy ) {
		f$pe$section_names = vector();

		for ( section, info in f$pe$section_info_table ) {
			local formatted_string: string = "";
			if (pe_log_section_entropy && pe_log_section_flags ) {
				formatted_string = fmt("%s:%s:%.2f", section, info$flags, info$entropy);
			}
			if (pe_log_section_entropy && ! pe_log_section_flags ) {
				formatted_string = fmt("%s:%.2f", section, info$entropy);
			}
			if (! pe_log_section_entropy && pe_log_section_flags ) {
				formatted_string = fmt("%s:%s", section, info$flags);
			}
			f$pe$section_names += formatted_string;
		}
	}
}


module Files;

# This is a way of bypassing Zeek's automatic PE analysis using its own PE
# analyzer.  It helps prevent duplicate events on Zeek 4.0 and before, where
# there's no API to disable file analyzers and so Spicy .evt can't rely
# on the 'replaces' setting to help substitute for Zeek's builtin PE analyzer.
# This wouldn't prevent someone from manually using Zeek's builtin PE
# via Files::add_analyzer(), but it work work for most cases (also, when using
# 'replaces' someone could still end up bypassing via Files::enable_analyzer()
# and somehow end up getting duplicates if they're motivated enough).
event zeek_init() &priority=-10
	{
	local pe_tag = Files::ANALYZER_PE;

	if ( pe_tag !in Files::mime_types )
		return;

	for ( mt in Files::mime_types[pe_tag] )
		delete Files::mime_type_to_analyzers[mt][pe_tag];

	delete Files::mime_types[pe_tag];
	}
