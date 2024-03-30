## Usage

```console
PS > openfsdecrypt.exe -k ***.bin -i ***.app -o ***.img
```

## Bonus

To mount decrypted `*.img` files, OSFMount can be used.

To mount differential VHDs:

```console
PS > Set-VHD H:\internal_1.vhd -ParentPath G:\internal_0.vhd
PS > Mount-VHD H:\internal_1.vhd -ReadOnly
```
