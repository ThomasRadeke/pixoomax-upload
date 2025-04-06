# pixoomax-upload
Upload images to the internal storage of the Divoom Pixoo-Max 32x32 pixel display.

This project is based on [virtualabs/pixoo-client](https://github.com/virtualabs/pixoo-client) but has been changed in a few ways:

- Added ability to upload pictures and animations to internal device galleries. Uploaded images will persist over reboots. Previous work only supported drawing a single image or animation until the device was turned off.
- Fixed animation encoding - GIFs will now play their entire length and loop correctly. Also, variable frame speed GIFs are supported (see Known Issues).
- Removed any functionality that is unrelated to uploading images.

If you need gallery uploading for Divoom's Pixoo 16x16 pixel display, please see [ThomasRadeke/pixoo-client-upload](https://github.com/ThomasRadeke/pixoo-client-upload).

## Dependencies
Needs Python3 `Pillow`, same as [virtualabs/pixoo-client](https://github.com/virtualabs/pixoo-client).

## How to use

Establish a BT connection to your Pixoo-Max and find out your MAC address. You can use the included `discover_devices.py` for this (notice: needs python-bluez installed).

### General usage:
`python pixoomax.py <MAC address> <command> <arguments>`

### Uploading images to internal device storage
The Pixoo-Max has 3 galleries that allow up to 17 pictures or animations to be stored in each. Galleries can be switched on-device by pressing the "light" button on the side of the device. The Pixoo-Max will also automatically switch to a specific gallery after uploading.

To upload images to the device, run:

`python pixoomax.py <MAC address> upload <gallery index> <files>`

where "gallery index" can be `1`, `2` or `3` and files can be up to 17 files with `.jpg`, `.png` or `.gif` extension, separated by spaces. Remember to quote your file names if the paths contain spaces.

Example:

`python pixoomax.py 11:75:58:xx:xx:xx upload 1 image1.png animation1.gif image2.jpg`

This will upload 3 images to gallery 1.

### Deleting an internal gallery
In case one of your galleries ends up corrupt, you can use the "deletegallery <1, 2 or 3>" command to clear the respective gallery storage:

`python pixoomax.py <MAC address> deletegallery <gallery index>`

## Known issues

- While the amount of internal storage space per gallery is bigger than the Pixoo's, keep in mind that when trying to upload long animations, the Pixoo-Max might behave in unexpected ways: e.g. crashing/freezing, spontaneously restarting or simply doing nothing. If you encounter problems, hold down the power button for several seconds, until the Pixoo-Max turns off.
- GIFs with variable frame speed are not natively supported by the Pixoo-Max firmware. This code uses a compromise and simulates variable frame speeds by finding the frame with the shortest display time and duplicating other frames a number of times. Example: a 2-frame GIF where the first frame is shown for 200ms and the second for 1000ms. The overall playback speed will then be set to 200ms per frame; the first frame is shown once and the second frame is shown 5 times to compensate. The drawback of this method is that accurate frame timings cannot be preserved, as every frame duration is a multiple of the shortest duration. This could be improved by finding the smallest multiplier that allows for all encountered timings and duplicating ALL frames accordingly, but that would increase the animation size considerably - possibly beyond the storage space limit.
- This code does not provide any other functionality than uploading images to, and deleting galleries.
- Uploading PNGs that have been converted to 8-bit palette mode might produce errors. Please use 24bit PNGs instead.
