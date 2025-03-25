#!/usr/bin/env python3

import sys
import re
import string

def camel_case(str_):
    """Convert snake_case to CamelCase."""
    return string.capwords(str_, "_").replace("_", "")

def main():
    # Read input files
    with open('../docs/hermes-options.html.in', 'r') as f:
        html_templ = f.read()

    hvar1 = ""
    hvar2 = ""
    cppvar1 = ""
    cppvar2 = ""
    cppvar3 = ""
    conf_example = ""
    htmlvar = ""
    htmlexpl = ""

    # Process input
    for line in sys.stdin:
        line = line.strip()
        
        if not line or line.startswith('#') or line.startswith('*'):
            if line == '*clean*':
                htmlexpl = ""
            elif line.startswith('*'):
                line = line.replace('*', '#')
                conf_example += line + "\n"
                
                # Convert line for HTML
                line_html = line.lstrip('#').replace('>', '&gt;')
                htmlexpl += line_html + "\n"
            continue

        parts = line.split(',')
        parts = [p.strip() for p in parts]

        type_str = parts[0]
        var_name = parts[1]
        default_val = parts[2]

        # Modify type for lists
        if 'list' in type_str:
            type_str = 'list<string>'

        camel_name = camel_case(var_name)

        # Generate header variables
        hvar1 += f"{type_str} {var_name};\n"
        hvar2 += f"{type_str}& get{camel_name}();\n"

        # Generate cpp variables
        if 'list' in type_str:
            cppvar1 += f"{var_name} = Configfile::parseAsList({default_val});\n"
        else:
            cppvar1 += f"{var_name} = {default_val};\n"

        cppvar2 += f"PARSE_{parts[0].upper()}(\"{var_name}\", {var_name})\n"
        cppvar3 += f"GET_VAR(get{camel_name}, {var_name}, {type_str}&)\n"

        # Generate config example
        conf_example += f"{var_name} = {default_val}\n\n"

        # Generate HTML
        html_temp = html_templ.replace('%type%', parts[0]) \
                              .replace('%name%', var_name) \
                              .replace('%default%', default_val) \
                              .replace('%explanation%', htmlexpl)
        htmlvar += html_temp
        htmlexpl = ""

    # Clean up variables
    for var in [cppvar1, cppvar2, cppvar3, hvar1, hvar2, conf_example]:
        var = var.rstrip()

    # Read and write Configfile.cpp
    with open('../src/Configfile.cpp.in', 'r') as f:
        cpp_str = f.read()

    cpp_str = cpp_str.replace('%templ_default_values%', cppvar1) \
                     .replace('%templ_parsevars%', cppvar2) \
                     .replace('%templ_getmethods%', cppvar3)

    with open('Configfile.cpp', 'w') as f:
        f.write(cpp_str)

    # Read and write Configfile.h
    with open('../src/Configfile.h.in', 'r') as f:
        h_str = f.read()

    h_str = h_str.replace('%templ_privateattribs%', hvar1) \
                 .replace('%templ_publicmethods%', hvar2)

    with open('Configfile.h', 'w') as f:
        f.write(h_str)

    # Write hermesrc.example
    with open('../dists/hermesrc.example', 'w') as f:
        f.write(conf_example)

    # Write hermes-options.html
    with open('../docs/hermes-options.html', 'w') as f:
        f.write(htmlvar)

if __name__ == "__main__":
    main()
