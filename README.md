# Userland exec

This is a userland exec function using grugq's excellent
[guide](https://grugq.github.io/docs/ul_exec.txt)

This is more of a proof of concept than something that is intended to be used.

There are basically no checks (think of checking if the file is executable).

Most of the special cases for the values in the elf file are also not dealt
with. An example of this would be the following text from the man elf page

```
This member holds the number of entries in the program
header table.  Thus the product of e_phentsize and e_phnum
gives the table's size in bytes.  If a file has no program
header, e_phnum holds the value zero.

If the number of entries in the program header table is
larger than or equal to PN_XNUM (0xffff), this member
holds PN_XNUM (0xffff) and the real number of entries in
the program header table is held in the sh_info member of
the initial entry in section header table.  Otherwise, the
sh_info member of the initial entry contains the value
zero.
```

`alloca` is used as opposed to `mmap` as that was required by the prof of the
course.
