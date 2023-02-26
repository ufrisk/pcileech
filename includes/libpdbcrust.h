// C library wrapper around the rust PDB crate and related useful utilities.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//

#include <stddef.h>
#include <stdbool.h>

/*
* Open a PDB file given its full path and return a handle to it.
* The handle should be closed by calling pdbcrust_close(). 
*/
size_t pdbcrust_open(
    char *sz_pdb_full_path
);

/*
* Close a PDB handle and free its resources.
*/
void pdbcrust_close(
    size_t hnd
);

/*
* Ensure that a PDB file exists on the specified path and upon success return
* the full file path in sz_pdb_path_result. If the PDB file does not exist it
* may optionally be downloaded from the Microsoft symbol server.
* -- sz_pdb_basepath      = base path (directory must exist).
* -- sz_pdb_guidage       = the combined GUID+AGE in uppercase hexascii string.
* -- sz_pdb_name          = the pdb file name.
* -- is_mspdb_download    = download the PDB from the microsoft symbol server.
* -- len_path_path_result = byte length of sz_pdb_path_result.
* -- sz_pdb_path_result   = buffer to receive full pdb file path on success.
* -- return
*/
bool pdbcrust_pdb_download_ensure(
    char *sz_pdb_basepath,
    char *sz_pdb_guidage,
    char *sz_pdb_name,
    bool is_mspdb_download,
    size_t len_path_path_result,
    char *sz_pdb_path_result
);

/*
* Retrieve a symbol offset given a symbol name.
* -- hnd
* -- sz_symbol_name = the symbol name to retrieve
* -- return = the symbol offset on success. zero on fail.
*/
unsigned int pdbcrust_symbol_offset(
    size_t hnd,
    char *sz_symbol_name
);

/*
* Retrieve a symbol name given an offset.
* -- hnd
* -- symbol_offset = the symbol offset.
* -- len_symbol_name
* -- sz_symbol_name
* -- displacement = the displacement, currently not functional.
* -- return
*/
bool pdbcrust_symbol_name_from_offset(
    size_t hnd,
    unsigned int symbol_offset,
    size_t len_symbol_name,
    char *sz_symbol_name,
    unsigned int *displacement
);

/*
* Retrieve the size of a type / struct.
* -- hnd
* -- sz_type_name
* -- return = the type size on success, 0 on fail.
*/
unsigned int pdbcrust_type_size(
    size_t hnd,
    char *sz_type_name
);

/*
* Retrieve the child offset inside a type/struct.
* -- hnd
* -- sz_type_name
* -- sz_type_child
* -- offset_type_child = ptr to receive the child offset on success.
* -- return
*/
bool pdbcrust_type_child_offset(
    size_t hnd,
    char *sz_type_name,
    char *sz_type_child,
    unsigned int *offset_type_child
);
