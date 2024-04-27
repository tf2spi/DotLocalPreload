#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include <winnt.h>
#include <psapi.h>
#include <assert.h>
#include <stdarg.h>

// Advised file alignment for PE files
#define FILE_ALIGN 512

// Clamp untrusted page sizes in PE files
#define MIN_PAGE_SIZE FILE_ALIGN
#define MAX_PAGE_SIZE 0x40000000u

#define INSTALL_DIR "install.exe.local"
const uint32_t DOS_STUB[] = 
{
    0x00905a4d, 0x00000003, 0x00000004, 0x0000ffff,
    0x000000b8, 0x00000000, 0x00000040, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                        // e_lfanew
    0x00000000, 0x00000000, 0x00000000, 0x00000108,
    0x0eba1f0e, 0xcd09b400, 0x4c01b821, 0x685421cd,
    0x70207369, 0x72676f72, 0x63206d61, 0x6f6e6e61,
    0x65622074, 0x6e757220, 0x206e6920, 0x20534f44,
    0x65646f6d, 0x0a0d0d2e, 0x00000024, 0x00000000,
    0x4841d208, 0x1b2fb34c, 0x1b2fb34c, 0x1b2fb34c,
    0x1a2ccb07, 0x1b2fb345, 0x1a2acb07, 0x1b2fb3de,
    0x1a2bcb07, 0x1b2fb346, 0x1b2fb34c, 0x1b2fb34d,
    0x1a2ecb07, 0x1b2fb34f, 0x1b2eb34c, 0x1b2fb311,
    0x1a2a328e, 0x1b2fb364, 0x1a2b328e, 0x1b2fb35c,
    0x1a2c328e, 0x1b2fb35d, 0x1a2b31be, 0x1b2fb34d,
    0x1a2f31be, 0x1b2fb34d, 0x1a2d31be, 0x1b2fb34d,
    0x68636952, 0x1b2fb34c, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
};

static int verrf(const char *fmt, va_list ap)
{
	fflush(stdout);
	return vfprintf(stderr, fmt, ap);
}

static int errf(const char *fmt, ...)
{
	int n;
	va_list ap;
	va_start(ap, fmt);
	n = verrf(fmt, ap);
	va_end(ap);
	return n;
}

static int perrf(DWORD code, const char *fmt, ...)
{
	char msgerr[256];
	int n;
	va_list ap;
	va_start(ap, fmt);
	n = verrf(fmt, ap);
	va_end(ap);
	*msgerr = 0;
	DWORD fmtlen = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		msgerr,
		sizeof(msgerr),
		NULL);
	n += errf(" (error code 0x%08X)\n", code);
	return n;
}

#define DBGF(...) errf(__VA_ARGS__)
#define ERRF(...) errf(__VA_ARGS__)
#define PERRF(...) perrf(__VA_ARGS__)
#define OUTF(...) printf(__VA_ARGS__)

union IMAGE_NT_HEADERS
{
	IMAGE_NT_HEADERS32 h32;
	IMAGE_NT_HEADERS64 h64;
};

struct IMAGE_EXPORT_DIRECTORY
{
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfAddresses;
	DWORD NumberOfNames;
	DWORD AddressOfExports;
	DWORD AddressOfNames;
	DWORD AddressOfOrdinals;
};

struct IMAGE
{
	HMODULE module;
	void *base;
	uint32_t size;
	uint32_t opthdrsize;
	uint32_t nthdrsize;
	uint32_t pgsize;
	IMAGE_DOS_HEADER *dos;
	union IMAGE_NT_HEADERS *nt;
	IMAGE_DATA_DIRECTORY *directories;
	uint32_t dircnt;
	uint32_t error;
};

#define FWDHDR_BASE \
	uint8_t dos[sizeof(DOS_STUB)]; \
	union IMAGE_NT_HEADERS nt; \
	IMAGE_SECTION_HEADER shdrspace[1]; \
	IMAGE_EXPORT_DIRECTORY expspace \


struct fwdheader_base
{
	FWDHDR_BASE;
};

struct fwdheader
{
	FWDHDR_BASE;
	uint8_t alignment[2 * FILE_ALIGN - sizeof(struct fwdheader_base)];
	uint8_t alignend;
	uint32_t opthdrsize;
	uint32_t ntsize;
	uint32_t pgsize;
	uint32_t size;
	union IMAGE_NT_HEADERS *headers;
	IMAGE_DATA_DIRECTORY *directories;
	struct IMAGE_EXPORT_DIRECTORY *exports;
	IMAGE_SECTION_HEADER *shdrs;
};

struct export
{
	char *name;
	uint16_t ordinal;
};

#define aligned(ptr) !((uintptr_t)(ptr) & (uintptr_t)(sizeof(*(ptr)) - 1))
static inline uintptr_t aligndown(uintptr_t addr, uintptr_t power)
{
	return addr & ~(power - 1);
}
static inline uintptr_t alignup(uintptr_t addr, uintptr_t power)
{
	return aligndown(addr + power - 1, power);
}
static inline uintptr_t cleanpagesize(uintptr_t pgsize)
{
	if (pgsize < MIN_PAGE_SIZE)
		return MIN_PAGE_SIZE;
	if (pgsize > MAX_PAGE_SIZE)
		return MAX_PAGE_SIZE;

	// Nice bit trick to get the biggest power of 2 below this quickly
	uintptr_t power = pgsize;
	while (power & (power - 1))
		power &= (power - 1);
	return alignup(pgsize, power);
}

#define rva_to_va(b, rva) (void *)((uintptr_t)b + rva)
static BOOL rva_size_bounded(uint32_t imgsize, uint32_t rva, uint32_t nmemb, uint32_t membsize)
{
	return rva < imgsize && (imgsize - rva) / membsize > nmemb;
}

static SYSTEM_INFO sysinfo;
static LPSYSTEM_INFO GetSystemInfoStatic(void)
{
	GetSystemInfo(&sysinfo);
	return &sysinfo;
}

static int sort_rva(void *ctx, const uint32_t *lhs, const uint32_t *rhs)
{
	const char *base = (const char *)ctx;
	return strcmp(base + *lhs, base + *rhs);
}

static int sort_exports(void *unused, const void *lhs, const void *rhs)
{
	(void)unused;
	const struct export *exportl = (const struct export *)lhs;
	const struct export *exportr = (const struct export *)rhs;

	// Sort by name then by ordinal
	if (exportl->name != NULL && exportr->name != NULL)
		return strcmp(exportl->name, exportr->name);
	else if (exportl->name != NULL && exportr->name == NULL)
		return -1;
	else if (exportl->name == NULL && exportr->name != NULL)
		return 1;
	return (int)exportl->ordinal - (int)exportr->ordinal;
}

static void sort_nametable(uint32_t *names, uint32_t count, struct IMAGE_EXPORT_DIRECTORY *dir)
{
	qsort_s(names, count, sizeof(*names), sort_rva, dir);
}

static void sort_exptable(struct export *table, size_t count)
{
	qsort_s(table, count, sizeof(*table), sort_exports, NULL);
}

static struct export *search_exptable(struct export *table, size_t count, const struct export needle)
{
	return (struct export *)bsearch_s(&needle, table, count, sizeof(*table), sort_exports, NULL);
}

// Free the memory if the grow fails
#define DYNMEM_INIT {NULL, 0, 0}
struct dynmem
{
	void *mem;
	size_t allocated;
	size_t size;
};
static void dynmem_free(struct dynmem *dynmem)
{
	assert(dynmem != NULL);
	free(dynmem->mem);
	dynmem->mem = NULL;
	dynmem->allocated = 0;
	dynmem->size = 0;
}
static void *dynmem_grow(struct dynmem *dynmem, size_t grow)
{
	assert(dynmem != NULL);
	size_t alloc = dynmem->allocated;
	size_t newsize = dynmem->size;
	if (SIZE_MAX - newsize < grow)
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		dynmem_free(dynmem);
		return NULL;
	}
	newsize += grow;
	if (dynmem->mem == NULL)
	{
		dynmem->mem = malloc(grow);
		if (dynmem->mem == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			dynmem->allocated = 0;
			dynmem->size = 0;
			return NULL;
		}
		dynmem->size = grow;
		dynmem->allocated = newsize;
		return dynmem->mem;
	}
	if (newsize > alloc)
	{
		if (newsize > (SIZE_MAX >> 1))
		{
			dynmem_free(dynmem);
			return NULL;
		}
		alloc = newsize << 1;
		void *tmp = realloc(dynmem->mem, alloc);
		if (tmp == NULL)
		{
			dynmem_free(dynmem->mem);
			return NULL;
		}
		dynmem->mem = tmp;
		dynmem->allocated = alloc;
	}
	dynmem->size = newsize;
	return dynmem->mem;
}

static void image_unmap(struct IMAGE *image)
{
	if (image != NULL)
	{
		DWORD error = image->error;
		if (image->module)
			FreeLibrary(image->module);
		memset(image, 0, sizeof(*image));
		image->error = error;
	}
}

static struct IMAGE image_map(const char *image)
{
	struct IMAGE img;
	memset(&img, 0, sizeof(img));
	HMODULE hModule = LoadLibraryExA(
		image,
		NULL,
		LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
		| LOAD_LIBRARY_AS_IMAGE_RESOURCE
	);
	MODULEINFO info;
	if (hModule == NULL)
	{
		img.error = GetLastError();
		return img;
	}

	// LoadLibrary mapped everything properly so trust the headers
	// Additionally, hModule uses low bits as flags so mask those off
	// to get the base address. We know it's aligned on a page address.
	img.module = hModule;
	img.base = (void *)((uintptr_t)hModule & ~(uintptr_t)(GetSystemInfoStatic()->dwPageSize - 1));
	img.dos = (IMAGE_DOS_HEADER *)img.base;
	img.nt = (union IMAGE_NT_HEADERS *)rva_to_va(img.dos, img.dos->e_lfanew);
	switch (img.nt->h32.OptionalHeader.Magic)
	{
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		    img.directories = &img.nt->h64.OptionalHeader.DataDirectory[0];
		    img.dircnt = img.nt->h64.OptionalHeader.NumberOfRvaAndSizes;
		    img.size = img.nt->h64.OptionalHeader.SizeOfImage;
		    img.pgsize = img.nt->h64.OptionalHeader.SectionAlignment;
		    img.nthdrsize = sizeof(img.nt->h64);
		    img.opthdrsize = sizeof(img.nt->h64.OptionalHeader);
		    break;
	    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		    img.directories = &img.nt->h32.OptionalHeader.DataDirectory[0];
		    img.dircnt = img.nt->h32.OptionalHeader.NumberOfRvaAndSizes;
		    img.size = img.nt->h32.OptionalHeader.SizeOfImage;
		    img.pgsize = img.nt->h32.OptionalHeader.SectionAlignment;
		    img.nthdrsize = sizeof(img.nt->h32);
		    img.opthdrsize = sizeof(img.nt->h32.OptionalHeader);
		    break;
	    default:
		    // Resets to default values so nothing is returned
		    img.error = ERROR_INVALID_DATA;
		    image_unmap(&img);
	}
	return img;
}

static struct export *exports_from_dir(const void *base, size_t imgsize, const struct IMAGE_EXPORT_DIRECTORY *expdir, size_t *expc)
{
	assert(expc != NULL);
	struct dynmem mem = DYNMEM_INIT;
	struct export *exports = NULL;
	size_t addrcount = expdir->NumberOfAddresses;
	size_t namecount = expdir->NumberOfNames;
	if (namecount > addrcount)
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}
	if (!rva_size_bounded(SIZE_MAX, 0, addrcount, sizeof(*exports)))
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}
	exports = (struct export *)dynmem_grow(&mem, addrcount * sizeof(*exports));
	if (exports == NULL)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}
	for (uint32_t i = 0; i < addrcount; i++)
	{
		exports[i].ordinal = i;
		exports[i].name = NULL;
	}

	// The tables must be in bounds for the image
	uint32_t *names = rva_to_va(base, expdir->AddressOfNames);
	uint16_t *ordinals = rva_to_va(base, expdir->AddressOfOrdinals);
	if (!rva_size_bounded(imgsize, expdir->AddressOfNames, namecount, sizeof(*names))
		|| !rva_size_bounded(imgsize, expdir->AddressOfOrdinals, namecount, sizeof(*ordinals)))
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}

	// Not sure if they're allowed to be unaligned,
	// so check but don't implement that case.
	if (!aligned(names) || !aligned(ordinals))
	{
		ERRF("Reading unaligned names and ordinals in export section unimplemented!\n");
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return NULL;
	}

	for (uint32_t i = 0; i < namecount; i++)
	{
		uint16_t ordinal = ordinals[i];
		if (ordinal >= addrcount || names[i] == 0 || names[i] >= imgsize)
		{
			continue;
		}
		const char *s = (const char *)rva_to_va(base, names[i]);
		size_t slen = strnlen(s, imgsize - names[i]);

		size_t prev = mem.size;
		exports = (struct export *)dynmem_grow(&mem, slen + 1);
		if (exports == NULL)
			return NULL;
		char *dst = (char *)exports + prev;
		exports[ordinal].name = (char *)prev; 
		memcpy(dst, s, slen);
		dst[slen] = 0;
	}

	// realloc is still free to move memory or fail
	// while shrinking memory so check for that.
	void *tmp = realloc(exports, mem.size);
	if (tmp != NULL)
	{
		exports = (struct export *)tmp;
	}

	// Relocate name entries
	for (size_t i = 0; i < addrcount; i++)
	{
		if (exports[i].name != NULL)
			exports[i].name += (uintptr_t)exports;
	}

	*expc = addrcount;
	return exports;
}

static struct export *exports_from_image(struct IMAGE *image, char *name, size_t *expc, struct IMAGE_EXPORT_DIRECTORY *dirp)
{
	assert(image != NULL && expc != NULL);
	if (image->error)
	{
		return NULL;
	}
	if (!image->module)
	{
		image->error = ERROR_BAD_ARGUMENTS;
		return NULL;
	}

	// If export directory not present, assume
	// it's because there are no exports
	IMAGE_DATA_DIRECTORY *expdirptr = &image->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (image->dircnt <= IMAGE_DIRECTORY_ENTRY_EXPORT
		|| expdirptr->VirtualAddress == 0
		|| expdirptr->Size < sizeof(struct IMAGE_EXPORT_DIRECTORY))
	{
		struct export *exports = malloc(1);
		if (exports == NULL)
		{
			image->error = ERROR_NOT_ENOUGH_MEMORY;
			return NULL;
		}
		*expc = 0;
		return exports;
	}
	IMAGE_DATA_DIRECTORY expdir = *expdirptr;

	// Make sure that the export directory is inside the DLL
	if (!rva_size_bounded(image->size, expdir.VirtualAddress, expdir.Size, 1))
	{
		image->error = ERROR_INVALID_DATA;
		return NULL;
	}

	// Do a memcpy in case directory is unaligned
	struct IMAGE_EXPORT_DIRECTORY directory;
	const void *base = image->base;
	size_t imgsize = image->size;
	memcpy(&directory,
		(struct IMAGE_EXPORT_DIRECTORY *)rva_to_va(base, expdir.VirtualAddress),
		sizeof(directory));
	if (dirp != NULL)
	{
		*dirp = directory;
	}
	if (name != NULL)
	{
		if (directory.Name > imgsize)
		{
			image->error = ERROR_INVALID_DATA;
			return NULL;
		}
		const char *imgname = (const char *)rva_to_va(base, directory.Name);
		DWORD slen = strnlen(imgname, imgsize - directory.Name);
		if (slen > MAX_PATH - 1)
			slen = MAX_PATH - 1;
		memcpy(name, imgname, slen);
		name[slen] = 0;
	}

	return exports_from_dir(base, imgsize, &directory, expc);
}

__declspec(dllexport) int HelloWorld(void)
{
	OUTF("Hello World!\n");
	return 0;
}

static struct export *exports_from_path(const char *path, char *name, size_t *expc, struct fwdheader *hdr)
{
	struct IMAGE image = image_map(path);
	if (!image.module)
	{
		PERRF(image.error, "Failed to map '%s' as DLL", path);
		return NULL;
	}
	OUTF("Image '%s' mapped!\n", path);
	struct IMAGE_EXPORT_DIRECTORY *dirp = NULL;
	if (hdr != NULL)
	{
		hdr->headers = &hdr->nt;
		hdr->opthdrsize = image.opthdrsize;
		hdr->ntsize = image.nthdrsize;
		hdr->pgsize = image.pgsize;
		memcpy(&hdr->nt, image.nt, image.nthdrsize);
		hdr->directories = rva_to_va(hdr->headers,
			image.nthdrsize - IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
		hdr->shdrs = (IMAGE_SECTION_HEADER *)rva_to_va(hdr->directories, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
		hdr->exports = (struct IMAGE_EXPORT_DIRECTORY *)rva_to_va(hdr->shdrs, sizeof(hdr->shdrspace));
		hdr->size = image.nthdrsize + sizeof(hdr->expspace) + sizeof(hdr->shdrspace);
		dirp = hdr->exports;
	}
	struct export *exports = exports_from_image(&image, name, expc, dirp);
	image_unmap(&image);
	if (exports == NULL)
	{
		PERRF(image.error, "Failed to get exports from '%s'", path);
		return NULL;
	}
	OUTF("Exports extracted from '%s'\n", path);
	return exports;
}

static void print_export(const struct IMAGE_EXPORT_DIRECTORY *dir, uint32_t i)
{
	const char *expname = (const char *)rva_to_va(dir,
		((uint32_t *)rva_to_va(dir, dir->AddressOfNames))[i]
	);
	const uint16_t unbiased = ((uint16_t *)rva_to_va(dir, dir->AddressOfOrdinals))[i];
	if (unbiased < dir->NumberOfAddresses)
	{
		const char *fwd = (const char *)rva_to_va(dir,
			((uint32_t *)rva_to_va(dir, dir->AddressOfNames))[i]
		);
		OUTF("'%s' -> '%s' @ %hu\n", expname, fwd, unbiased);
	}
}

static struct IMAGE_EXPORT_DIRECTORY *add_export(
	struct dynmem *mem,
	uint32_t expc,
	const char *dll,
	const struct export fn,
	uint32_t *ip)
{
	char ord[8];
	char *expfunc = fn.name;
	struct IMAGE_EXPORT_DIRECTORY *dir = mem->mem;
	if (expfunc == NULL)
	{
		sprintf(ord, "#%hu", fn.ordinal + dir->Base);
		expfunc = ord;
	}
	size_t lhs = strlen(dll);
	size_t rhs = strlen(expfunc);
	size_t grow = lhs + rhs + 2;
	size_t ptr = mem->size;
	dir = (struct IMAGE_EXPORT_DIRECTORY *)dynmem_grow(mem, grow);
	if (dir == NULL || mem->size > UINT32_MAX)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		dynmem_free(mem);
		return NULL;
	}
	char *s = (char *)dir + ptr;
	memcpy(s, dll, lhs);
	s[lhs] = '.';
	memcpy(s + lhs + 1, expfunc, rhs + 1);

	// Ordinals correspond to entries in the export address table
	// so if the index overflows, the operation's a failure.
	uint16_t unbiased = fn.ordinal;
	if (unbiased >= expc)
	{
		ERRF("unbiased: %d, expc: %d\n", unbiased, (int)expc);
		SetLastError(ERROR_INVALID_DATA);
		dynmem_free(mem);
		return NULL;
	}
	((uint32_t *)rva_to_va(dir, dir->AddressOfExports))[unbiased] = ptr;
	if (fn.name != NULL)
	{
		uint32_t i = *ip;
		// Set RVA of name to 0 if it is not present
		((uint32_t *)rva_to_va(dir, dir->AddressOfNames))[i] = (ptr + lhs + 1);
		((uint16_t *)rva_to_va(dir, dir->AddressOfOrdinals))[i] = unbiased;
		*ip = i + 1;
	}
	return dir;
}

static uint32_t clean_name(char *dll)
{
	// We don't want absolute paths at all
	char *suffix = strrchr(dll, '\\');
	if (suffix++ != NULL)
	{
		char *lhs = dll;
		while (*lhs++ = *suffix++)
			;
	}
	// Strip the suffix and return it
	// 3 letter extensions are good enough
	suffix = strrchr(dll, '.');
	uint32_t ext = 0;
	if (suffix != NULL)
	{
		strncpy((char *)&ext, suffix, sizeof(ext));
		*suffix = 0;
	}
	return ext;
}

static char *append_suffix(char *name, size_t max, uint32_t suffix)
{
	size_t i = strlen(name);
	size_t remaining = max - i - 1;
	assert(remaining <= max);
	if (remaining > sizeof(suffix))
		remaining = sizeof(suffix);
	strncpy(name + i, (const char *)&suffix, remaining);
	name[i + remaining] = 0;
	return name;
}

static BOOL install(const char *prev, const char *dir, const char *file)
{
	char path[2 * MAX_PATH];
	snprintf(path, sizeof(path), "%s\\%s", dir, file);
	return CopyFile(prev, path, FALSE);
}

static BOOL WriteFileExact(HANDLE hFile, const void *buf, uint32_t len)
{
	DWORD nRead;
	while (len != 0)
	{
		if (!WriteFile(hFile, buf, len, &nRead, NULL))
			return FALSE;
		buf = (const char *)buf + nRead;
		len -= nRead;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		ERRF("Usage: %s PreloadDLL ReferenceDLL\n", *argv);
		return EXIT_FAILURE;
	}

	struct fwdheader hdr;
	memset(&hdr, 0, sizeof(hdr));

	char outname[MAX_PATH];
	char plname[MAX_PATH];
	char refname[MAX_PATH];
	const char *preload = argv[1];
	const char *reference = argv[2];
	size_t plexpc = 0;
	size_t refexpc = 0;
	struct export *plexps = exports_from_path(preload, plname, &plexpc, NULL);
	if (plexps == NULL)
	{
		return EXIT_FAILURE;
	}
	struct export *refexps = exports_from_path(reference, refname, &refexpc, &hdr);
	if (refexps == NULL)
	{
		return EXIT_FAILURE;
	}
	uint32_t refnamec = hdr.exports->NumberOfNames;
	refexpc = hdr.exports->NumberOfAddresses;

	// Allocate memory for exported function RVAs as well as exported name RVAs/ordinals
	struct IMAGE_EXPORT_DIRECTORY *expdir = NULL;
	if (!rva_size_bounded(SIZE_MAX, sizeof(*expdir), refexpc, sizeof(uint32_t))
		|| !rva_size_bounded(SIZE_MAX,
			sizeof(*expdir) + refnamec * sizeof(uint32_t),
			refnamec, sizeof(uint32_t) + sizeof(uint16_t)))
	{
		ERRF("Number of exports too big to fit in memory!\n");
		return EXIT_FAILURE;
	}
	struct dynmem mem = DYNMEM_INIT;
	expdir = (struct IMAGE_EXPORT_DIRECTORY *)dynmem_grow(
		&mem,
		sizeof(*expdir)
		+ refnamec * 3 * sizeof(uint16_t)
		+ refexpc * sizeof(uint32_t)
	);
	if (expdir == NULL)
	{
		PERRF(GetLastError(), "Failed to allocate initial export directory table!");
		return EXIT_FAILURE;
	}
	expdir->Characteristics = hdr.exports->Characteristics;
	expdir->TimeDateStamp = hdr.exports->TimeDateStamp;
	expdir->MajorVersion = hdr.exports->MajorVersion;
	expdir->MinorVersion = hdr.exports->MinorVersion;
	expdir->NumberOfAddresses = hdr.exports->NumberOfAddresses;
	expdir->AddressOfExports = sizeof(*expdir);
	expdir->AddressOfNames = expdir->AddressOfExports + sizeof(uint32_t) * refexpc;
	expdir->AddressOfOrdinals = expdir->AddressOfNames + sizeof(uint32_t) * refnamec;
	expdir->Base = hdr.exports->Base;

	uint32_t plext = clean_name(plname);
	uint32_t refext = clean_name(refname);
	strcpy(outname, refname);
	snprintf(refname, sizeof(refname), "%sREF", refname);
	if (!_stricmp(plname, outname))
	{
		snprintf(plname, sizeof(plname), "%sPLD", plname);
	}

	sort_exptable(plexps, plexpc);
	uint32_t namei = 0;
	for (size_t i = 0; i < refexpc; i++)
	{
		const struct export export = refexps[i];
		const char *dllname = (search_exptable(plexps, plexpc, export) != NULL) ? plname : refname;
		if (dllname == plname)
		{
			if (export.name != NULL)
				OUTF("Preloading '%s'...\n", export.name);
			else
				OUTF("Preloading '#%hu'...\n", export.ordinal);
		}
		expdir = add_export(&mem, refexpc, dllname, export, &namei);
		if (expdir == NULL)
		{
			PERRF(GetLastError(), "Failed to add export '%s' to forwarder exports!", export);
			return EXIT_FAILURE;
		}
	}
	expdir->NumberOfNames = namei;
	size_t name_rva = mem.size;
	expdir = (struct IMAGE_EXPORT_DIRECTORY *)dynmem_grow(
		&mem, strlen(append_suffix(outname, sizeof(outname), refext)) + 1
	);
	if (name_rva > UINT32_MAX || expdir == NULL)
	{
		PERRF(GetLastError(), "Failed to make room for DLL name in edata section!");
		return EXIT_FAILURE;
	}
	strcpy((char *)rva_to_va(expdir, name_rva), outname);
	expdir->Name = name_rva;

	// Dynamically create the PE file
	char tmppath[32];
	sprintf(tmppath, "dlp-tmp-%x-%x", GetCurrentProcessId(), GetTickCount());
	HANDLE hFile = CreateFileA(
		tmppath,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PERRF(GetLastError(), "Failed to create temporary file for forwarder!");
		return EXIT_FAILURE;
	}

	memcpy(hdr.dos, DOS_STUB, sizeof(DOS_STUB));
	uint32_t headsize = offsetof(struct fwdheader, alignend);
	uint32_t sectalign = cleanpagesize(hdr.pgsize);
	uint32_t filesize = alignup(headsize + mem.size, FILE_ALIGN);
	uint32_t imgsize = alignup(headsize, sectalign) + alignup(mem.size, sectalign);
	if (filesize < headsize || imgsize < filesize)
	{
		ERRF("Export directory too big for exporting!\n");
		return EXIT_FAILURE;
	}
	IMAGE_FILE_HEADER *filhdr = &hdr.nt.h64.FileHeader;
	filhdr->NumberOfSections = ARRAYSIZE(hdr.shdrspace);
	filhdr->PointerToSymbolTable = 0;
	filhdr->NumberOfSymbols = 0;
	filhdr->SizeOfOptionalHeader = hdr.opthdrsize;
	IMAGE_DATA_DIRECTORY *datadir;
	switch (hdr.ntsize)
	{
		case sizeof(hdr.nt.h64):
			IMAGE_OPTIONAL_HEADER64 *h64 = &hdr.nt.h64.OptionalHeader;
			h64->SizeOfCode = 0;
			h64->SizeOfInitializedData = filesize - headsize;
			h64->SizeOfUninitializedData = 0;
			h64->AddressOfEntryPoint = 0;
			h64->BaseOfCode = sectalign;
			h64->ImageBase = aligndown(h64->ImageBase, sectalign);
			h64->SectionAlignment = sectalign;
			h64->FileAlignment = FILE_ALIGN;
			h64->SizeOfImage = imgsize;
			h64->SizeOfHeaders = headsize;
			h64->CheckSum = 0;
			h64->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			memset(h64->DataDirectory, 0, sizeof(h64->DataDirectory));
			datadir = &h64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			break;
		case sizeof(hdr.nt.h32):
			IMAGE_OPTIONAL_HEADER32 *h32 = &hdr.nt.h32.OptionalHeader;
			h32->SizeOfCode = 0;
			h32->SizeOfInitializedData = filesize - headsize;
			h32->SizeOfUninitializedData = 0;
			h32->AddressOfEntryPoint = 0;
			h32->BaseOfCode = sectalign;
			h32->ImageBase = aligndown(h32->ImageBase, sectalign);
			h32->SectionAlignment = sectalign;
			h32->FileAlignment = FILE_ALIGN;
			h32->SizeOfImage = imgsize;
			h32->SizeOfHeaders = headsize;
			h32->CheckSum = 0;
			h32->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			memset(h32->DataDirectory, 0, sizeof(h32->DataDirectory));
			datadir = &h32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			break;
	}
	size_t padlen = FILE_ALIGN - (mem.size & (FILE_ALIGN - 1));
	if (padlen == FILE_ALIGN)
		padlen = 0;
	uint8_t pad[FILE_ALIGN - 1];
	memset(pad, 0, sizeof(pad));
	strncpy(hdr.shdrs->Name, ".rdata", sizeof(hdr.shdrs->Name));
	hdr.shdrs->Misc.VirtualSize = mem.size;
	hdr.shdrs->VirtualAddress = sectalign;
	hdr.shdrs->SizeOfRawData = mem.size + padlen;
	hdr.shdrs->PointerToRawData = headsize;
	hdr.shdrs->PointerToRelocations = 0;
	hdr.shdrs->PointerToLinenumbers = 0;
	hdr.shdrs->NumberOfRelocations = 0;
	hdr.shdrs->NumberOfLinenumbers = 0;
	hdr.shdrs->Characteristics = 0x40000040;
	datadir->VirtualAddress = hdr.shdrs->VirtualAddress;
	datadir->Size = mem.size;
	uint32_t names_rva = expdir->AddressOfNames;
	uint32_t *names = ((uint32_t *)rva_to_va(expdir, names_rva));
	uint32_t exports_rva = expdir->AddressOfExports;
	uint32_t *exports = ((uint32_t *)rva_to_va(expdir, exports_rva));
	uint32_t ordinals_rva = expdir->AddressOfOrdinals;
	uint16_t *ordinals = ((uint16_t *)rva_to_va(expdir, ordinals_rva));

	// Sort the name table like it should be in a DLL.
	// Then, we can recover the ordinals by sorting the reference exports
	// and then search for it by name which will return both name and ordinal.
	sort_nametable(names, namei, expdir);
	sort_exptable(refexps, refexpc);
	for (uint32_t i = 0, count = expdir->NumberOfNames; i < count; i++)
	{
		struct export export =
		{
			(char *)rva_to_va(expdir, names[i]),
			(uint16_t)~0,
		};
		struct export *selected = search_exptable(refexps, refexpc, export);
		if (selected != NULL)
			ordinals[i] = selected->ordinal;
		else
			ERRF("Export %u not found in export table?\n", i);
		names[i] += datadir->VirtualAddress;
	}
	for (uint32_t i = 0, count = expdir->NumberOfAddresses; i < count; i++)
	{
		exports[i] += datadir->VirtualAddress;
	}
	expdir->Name += datadir->VirtualAddress;
	expdir->AddressOfNames += datadir->VirtualAddress;
	expdir->AddressOfExports += datadir->VirtualAddress;
	expdir->AddressOfOrdinals += datadir->VirtualAddress;

	if (!WriteFileExact(hFile, &hdr, headsize)
		|| !WriteFileExact(hFile, expdir, mem.size)
		|| !WriteFileExact(hFile, pad, padlen))
	{
		PERRF(GetLastError(), "Failed to write forwarder DLL!");
		return EXIT_FAILURE;
	}

	OUTF("Installing DLLs!\n");
	if (!CreateDirectoryA(INSTALL_DIR, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		PERRF(GetLastError(), "Failed to create '%s' directory!", INSTALL_DIR);
		return EXIT_FAILURE;
	}
	if (!install(preload, INSTALL_DIR, append_suffix(plname, sizeof(plname), plext))
		|| !install(reference, INSTALL_DIR, append_suffix(refname, sizeof(refname), refext))
		|| !install(tmppath, INSTALL_DIR, outname))
	{
		PERRF(GetLastError(), "Failed to install preload and reference DLLs!");
		return EXIT_FAILURE;
	}
	OUTF("Installation Complete!\n");

	return 0;
}
