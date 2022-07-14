#include "imports.h"

auto get_import_address( IMAGE image, const char* name ) -> uintptr_t
{
    const auto dos = reinterpret_cast< IMAGE_DOS_HEADER * > ( image.base );

    const auto nt = reinterpret_cast< IMAGE_NT_HEADERS * >( image.base + dos->e_lfanew );

    const auto import_descriptor = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR * >( image.base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

    for ( unsigned int i = 0; import_descriptor[i].Characteristics; i++ )
    {
        auto first_thunk = reinterpret_cast< IMAGE_THUNK_DATA*> ( image.base + import_descriptor[i].FirstThunk );
        auto original_first_thunk = reinterpret_cast< IMAGE_THUNK_DATA* > ( image.base + import_descriptor[i].OriginalFirstThunk );

        for ( ; original_first_thunk->u1.Function; original_first_thunk++, first_thunk++ )
        {
            if ( original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                continue;
            }

            const auto import = reinterpret_cast< IMAGE_IMPORT_BY_NAME* > ( image.base + original_first_thunk->u1.AddressOfData );

            if ( strcmp( import->Name, name ) )
            {
                continue;
            }

            return first_thunk->u1.Function;
        }
    }

    return 0;
}

auto driver_entry( ) -> NTSTATUS
{
    get_import_address( utils::get_kernel_module( "win32kbase.sys" ), "ZwAllocateLocallyUniqueId" );

    return STATUS_SUCCESS;
}
