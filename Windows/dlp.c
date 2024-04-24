#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include <winnt.h>
#include <psapi.h>
#include <assert.h>

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
	uint32_t bits;
	IMAGE_DOS_HEADER *dos;
	union IMAGE_NT_HEADERS *nt;
	IMAGE_DATA_DIRECTORY *directories;
	uint32_t dircnt;
	uint32_t error;
};

#define rva_to_va(b, rva) (void *)((uintptr_t)b + rva)

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
	HMODULE hModule = LoadLibraryExA(image, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
	MODULEINFO info;
	if (hModule == NULL)
	{
		img.error = GetLastError();
		return img;
	}
	else if (!GetModuleInformation(GetCurrentProcess(), hModule, &info, sizeof(info)) )
	{
		FreeLibrary(hModule);
		return img;
	}

	// LoadLibrary mapped everything properly so trust the headers
	img.module = hModule;
	img.base = info.lpBaseOfDll;
	img.size = info.SizeOfImage;
	img.dos = (IMAGE_DOS_HEADER *)img.base;
	img.nt = (union IMAGE_NT_HEADERS *)rva_to_va(img.dos, img.dos->e_lfanew);
	switch (img.nt->h32.OptionalHeader.Magic)
	{
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		    img.directories = &img.nt->h64.OptionalHeader.DataDirectory[0];
		    img.dircnt = img.nt->h64.OptionalHeader.NumberOfRvaAndSizes;
		    img.bits = 64;
		    break;
	    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		    img.directories = &img.nt->h32.OptionalHeader.DataDirectory[0];
		    img.dircnt = img.nt->h32.OptionalHeader.NumberOfRvaAndSizes;
		    img.bits = 32;
		    break;
	    default:
		    // Resets to default values so nothing is returned
		    img.error = ERROR_INVALID_DATA;
		    image_unmap(&img);
	}
	return img;
}


static size_t exports_from_dir(const void *base, size_t size, const struct IMAGE_EXPORT_DIRECTORY *expdir, const char **exports, char *buffer, size_t buflen)
{
	if (expdir->NumberOfNames == 0)
		return 0;

	if (buffer == NULL)
		buflen = 0;
	uint32_t *names = rva_to_va(base, expdir->AddressOfNames);
	uint16_t *ordinals = rva_to_va(base, expdir->AddressOfOrdinals);
	uint32_t count = expdir->NumberOfNames;

	// They must be in bounds for the image
	// Not sure if they're allowed to be unaligned,
	// but we don't implement that case.
	if ((uintptr_t)names & 3
		|| (uintptr_t)ordinals & 1
		|| (size - expdir->AddressOfNames) / sizeof(*names) <= count
		|| (size - expdir->AddressOfOrdinals) / sizeof(*ordinals) <= count)
	{
		SetLastError(ERROR_INVALID_DATA);
		return 0;
	}

	size_t bufi = 0;
	size_t total = 0;
	for (uint32_t i = 0; i < count; i++)
	{
		char ord[8];
		const char *s;
		size_t slen;

		if (names[i] > 0 && names[i] < size)
		{
			s = (const char *)rva_to_va(base, names[i]);
			slen = strnlen(s, size - names[i]);
		}
		else
		{
			slen = snprintf(ord, sizeof(ord), "#%u", (uint16_t)ordinals[i]);
			s = ord;
		}
		total += slen + 1;
		if (bufi >= buflen)
			continue;

		size_t ncopy = buflen - bufi - 1;
		if (slen < ncopy)
			ncopy = slen;
		memcpy(buffer + bufi, s, ncopy);
		buffer[bufi + ncopy] = 0;
		if (exports != NULL)
			exports[i] = &buffer[bufi];
		bufi += ncopy + 1;
	}
	if (exports != NULL)
		exports[count] = NULL;
	return total;
}

static char **exports_from_image(struct IMAGE *image)
{
	assert(image != NULL);
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
	IMAGE_DATA_DIRECTORY expdir = image->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (image->dircnt <= IMAGE_DIRECTORY_ENTRY_EXPORT
		|| expdir.VirtualAddress == 0
		|| expdir.Size < sizeof(struct IMAGE_EXPORT_DIRECTORY))
	{
		char **exports = malloc(sizeof(*exports));
		if (exports == NULL)
		{
			image->error = ERROR_NOT_ENOUGH_MEMORY;
			return NULL;
		}
		*exports = NULL;
		return exports;
	}

	// Make sure that the export directory 
	if (expdir.VirtualAddress > image->size
		|| image->size - expdir.VirtualAddress < expdir.Size)
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

	size_t tablesize = exports_from_dir(base, imgsize, &directory, NULL, NULL, 0);
	if (tablesize == 0 && directory.NumberOfNames != 0)
	{
		image->error = ERROR_INVALID_DATA;
		return NULL;
	}

	char **exports = NULL;
	if ((SIZE_MAX - tablesize) / sizeof(*exports) < directory.NumberOfNames)
	{
		image->error = ERROR_INVALID_DATA;
		return NULL;
	}
	size_t vcnt = ((size_t)directory.NumberOfNames + 1);
	exports = (const char **)malloc(vcnt * sizeof(*exports) + tablesize);
	if (exports == NULL)
	{
		image->error = ERROR_NOT_ENOUGH_MEMORY;
		return NULL;
	}
	exports_from_dir(base, imgsize, &directory, exports, (char *)&exports[vcnt], tablesize);
	return exports;
}

__declspec(dllexport) int HelloWorld(void)
{
	printf("Hello World!\n");
}

int main(int argc, char **argv)
{
	const char *dll = *argv;
	if (argc > 1)
	{
		dll = argv[1];
	}
	struct IMAGE image = image_map(dll);
	if (!image.module)
	{
		fprintf(stderr, "Failed to map image!\n");
		return 1;
	}
	printf("Mapped image properly!\n");
	const char **exports = exports_from_image(&image);
	image_unmap(&image);
	if (exports == NULL)
	{
		fprintf(stderr, "Failed to get exports! %08X\n", image.error);
		return 1;
	}
	printf("Got some exports!\n");
	for (const char **iter = exports; *iter != NULL; iter++)
	{
		printf("\t%s\n", *iter);
	}
	return 0;
}
