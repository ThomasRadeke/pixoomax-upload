import sys
import socket
import os
import struct
import re
from time import sleep
from PIL import Image
from math import log10, ceil, floor

debug = False

#===================================================================
# GENERAL UTILITY FUNCTIONS

# Automatically converts a number to little-endian bytes.
# Byte sizes are chosen based on the number.
def to_bytes(number, num_bytes=1):
    format_type = 'B'
    
    # unsigned char, 1 byte
    if 0 <= number <= 255 or num_bytes == 1:
        format_type = 'B'
    # unsigned short, 2 bytes
    elif 0 <= number <= 65535  or num_bytes == 2:
        format_type = 'H'
    # unsigned int, 4 bytes
    elif 0 <= number <= 4294967295 or num_bytes == 3:
        format_type = 'I'
        
    return struct.pack(f'<{format_type}', number)

#===================================================================

# Class to encapsulate an entire gallery upload -
# encodes all images, prepares and sends SPP packets.
class PixooMaxGalleryUpload:

    #----------
    # Constants
    CMD_UPLOAD = 0x8c
    CMD_UPLOAD_SUB_START = 0x00
    CMD_UPLOAD_SUB_DATA = 0x01
    CMD_UPLOAD_SUB_END = 0x02
    CMD_MISC = 0xbd
    CMD_MISC_DELETE_GALLERY = 0x16 # delete an entire gallery on the device
    upload_delay = 0.01
    
    #----------
    # Fields
    
    # Index of the gallery to upload to. 1 byte.
    gallery_index = 0
    
    # Total size of entire datablock across all packets. 4 bytes.
    size = 0x00000000
    
    # List of images to prepare and upload.
    images = []
    
    # List of encoded packets.
    packets = []
    
    # Instance of self
    instance = None
    
    #--------
    # Methods
    
    #--------------------------------------------------------------------------
    def hex_str(self, string):
        """
        Convert a string to a hex representation.
        """
        result = ''
        for char in string:
            result = result + ("%0.2X" % char)
        return result
    
    def __init__(self, mac_address):
        """
        Constructor
        """
        self.mac_address = mac_address
        self.btsock = None
    
    #--------------------------------------------------------------------------
    
    # Add an image to the image list
    def add(self, image_filepath):
        if(len(self.images) < 17):
            if(os.path.isfile(image_filepath)):
                self.images.append(PixooMaxImage(image_filepath, len(self.images)))
            else:
                print("GalleryUpload add: File does not exist:", image_filepath)
        else:
            print("Cannot add more than 17 images, the Pixoo-Max doesn't support it.")
    
    #--------------------------------------------------------------------------
    
    # Get all images that have already been added.
    def get_images(self):
        return self.images
    
    #--------------------------------------------------------------------------
    
    # Set gallery index. The Pixoo-Max has 3 galleries, same as the Pixoo.
    def set_gallery_index(self, gallery_index):
        if 0 <= gallery_index <= 2:
            self.gallery_index = gallery_index
    
    #--------------------------------------------------------------------------
    
    # prepare PixooMaxPackets from images
    def prepare_packets(self):
        packets = []
        
        # start packet
        startpacket = PixooMaxPacket(self.CMD_UPLOAD, self.CMD_UPLOAD_SUB_START, [self.gallery_index])
        startpacket.set_totalsize(self.get_totalsize())
        
        # end packet
        endpacket = PixooMaxPacket(self.CMD_UPLOAD, self.CMD_UPLOAD_SUB_END, [])
        
        # prepare data chunks
        print("Preparing image data...")
        data_chunks = self.prepare_data_chunks()
        
        # add packets to list
        packets.append(startpacket)
        
        index = 0
        for data_chunk in data_chunks:
            packet = PixooMaxPacket(self.CMD_UPLOAD, self.CMD_UPLOAD_SUB_DATA, data_chunk)
            packet.set_totalsize(self.get_totalsize())
            packet.set_index(index)
            index = index+1
            packets.append(packet)
        
        packets.append(endpacket)
        self.packets = packets
        
    
    #--------------------------------------------------------------------------
    
    # Calculate and return total size of all images
    def get_totalsize(self):
        totalsize = 0
        for img in self.images:
            totalsize = totalsize+img.size()
        return totalsize
    
    #--------------------------------------------------------------------------
    
    # Prepare chunks from images
    def prepare_data_chunks(self):
        
        # First, calculate total size from all images
        totalsize = self.get_totalsize()
            
        self.size = totalsize
        #print(f"total size: {self.size}")
        
        # We now know the total size of the upload, which is required in the start packet
        # and every data packet.
        
        # Each chunk can be a maximum of 256 bytes.
        chunksize = 256
        
        chunks = []
        partial_data = []
        chunk_data = []
        
        #print("Number of images:", len(self.images))
        image = 0
        for img in self.images:
            #print("------------------")
            #print("image index:", image)
            image += 1
            
            # images contain at least 3 frames - 2 meta and one real data
            imagedata = img.get()
            
            # this is a hack to make all leftover partial data transfer into a last packet
            imagedata.append([])
            
            #print("num frames:", len(imagedata))
            
            # get size of current frame
            frame_index = 0
            for frame in imagedata:
            
                #print("\nframe index:", frame_index)
                frame_index = frame_index+1
                framesize = len(frame)
                
                if partial_data:
                    #print(f"Adding partial data from previous frame (size: {len(partial_data)})")
                    if len(partial_data) > chunksize:
                        #print("partial data is larger than chunk size:", len(partial_data))
                        for partial_index in range(0, ceil(len(partial_data)/chunksize)):
                            #print("------------------------------ new chunk")
                            #print("partial index:", partial_index)
                            start = chunksize*partial_index
                            end = chunksize*(partial_index+1)
                            chunk_data = partial_data[start:end]
                            # append chunk to list when it's full
                            if len(chunk_data) == chunksize:
                                chunks.append(chunk_data)
                                chunk_data = []
                    else:
                        # if partial data is smaller than chunk size, directly copy it
                        #print("partial data smaller than chunk size found")
                        chunk_data = partial_data
                
                spaceleft = chunksize - len(chunk_data)
                #print("space left:", spaceleft)
                
                # frame is larger than space left in this chunk
                if (framesize > spaceleft):
                    #print(f"Frame is partial (size: {framesize})")

                    chunk_data = chunk_data+frame[0:spaceleft]
                    #print(f"adding partial frame ({len(frame[0:spaceleft])})")
                    partial_data = frame[spaceleft:]
                else:
                    #print(f"Adding whole frame ({len(frame)})")
                    chunk_data = chunk_data+frame
                    partial_data = []
                
                #print("chunk data:", chunk_data)
                #print("partial data:", partial_data)
                
                spaceleft = chunksize - len(chunk_data)
                #print("-- space left after adding frame:", spaceleft)
                #print("-- partial data size:", len(partial_data))
            
                # If chunk is full, start next chunk.
                # Always make sure there is enough space for an entire image
                # header with 6 bytes; otherwise put that into the next chunk.
                if spaceleft <= 6:
                    chunks.append(chunk_data)
                    chunk_data = []
                    spaceleft = chunksize
                    #print("------------------------------ new chunk")
            #print("--- all frames done")
        #print("--- all images done")
        
        # deal with left-over partial and chunk data from last frame
        #print("partial data:", partial_data)
        # add left-over chunk data from last frame
        if chunk_data:
            chunks.append(chunk_data)

        #print("___________________________________________________")
        
        #for chunk in chunks:
        #    print("chunk size:", len(chunk))
        #    print(chunk)
        #    print("")
        
        return chunks
    
    #--------------------------------------------------------------------------
    
    # Connect to Pixoo-Max's SPP socket
    def connect(self):
        if not debug:
            self.btsock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            self.btsock.connect((self.mac_address, 1))
        
        # Wait a bit after connecting
        sleep(0.1)

    #--------------------------------------------------------------------------

    # Calculate SPP frame checksum
    def __spp_frame_checksum(self, args):
        return sum(args[1:])&0xffff

    #--------------------------------------------------------------------------

    # Encode SPP frame for given data
    def __spp_frame_encode(self, cmd, args):
        payload_size = len(args) + 3

        # create our header
        frame_header = [0x01, payload_size & 0xff, (payload_size >> 8) & 0xff, cmd]

        # concatenate our args (byte array)
        frame_buffer = frame_header + args

        # compute checksum (first byte excluded)
        cs = self.__spp_frame_checksum(frame_buffer)

        # create our suffix (including checksum)
        frame_suffix = [cs&0xff, (cs>>8)&0xff, 2]
        
        final_frame = frame_buffer+frame_suffix
        
        # uncomment to see the hex stream that gets sent.
        #print(self.hex_str(final_frame))
        
        # slow down the upload a bit
        sleep(self.upload_delay)
        
        # return output buffer
        return final_frame

    #--------------------------------------------------------------------------

    def send(self, cmd, args):
        """
        Send data to SPP.
        """
        spp_frame = self.__spp_frame_encode(cmd, args)
        
        if not debug:
            if self.btsock is not None:
                nb_sent = self.btsock.send(bytes(spp_frame))
                
    #--------------------------------------------------------------------------
    
    def do_upload(self):
        if not self.packets:
            self.prepare_packets()
            
            for i, packet in enumerate(self.packets):
                packetbytes = packet.get()
                result = ""
                for byte in packetbytes:
                    result = result + "%0.2X" % byte
            
                #print(result)
                print("\rSending packet {}/{}... ".format(i+1, len(self.packets)), end='')
                
                result = [int(result[i:i+2], 16) for i in range(0, len(result), 2)]
                
                if not debug:
                    if self.btsock is not None:
                        sleep(0.01)
                        nb_sent = self.btsock.send(bytes(result))
                    else:
                        print("Error: Bluetooth socket not connected.")
            print("Done.")
    
    #--------------------------------------------------------------------------
        
    def debug(self):
        for packet in self.packets:
            bytes = packet.get()
            result = ""
            for byte in bytes:
                result = result + "%0.2X" % byte
            print(result)
            
    #--------------------------------------------------------------------------
    
    # If something goes wrong while uploading and a gallery becomes corrupted,
    # use this command to reset the gallery and delete all images.
    def delete_gallery(self, gallery_index):
        self.send(self.CMD_MISC, [self.CMD_MISC_DELETE_GALLERY, gallery_index & 0xff])
    
#===================================================================

class PixooMaxPacket:
    
    #----------
    # Constants
    
    MAX_PACKET_SIZE = 266
    PACKET_START = 0x01
    PACKET_END = 0x02
    
    #----------
    # Fields
    size = 0x0000
    command = 0x00
    subcommand = 0x00
    totalsize = 0x00000000
    index = 0x0000
    data = []
    checksum = 0x0000

    #----------
    # Methods
    
    def __init__(self, command, subcommand, data):
        self.set_command(command, subcommand)
        self.set_data(data)
        self.calculate_checksum()
    
    #--------------------------------------------------------------------------
    
    def set_command(self, command, subcommand):
        self.command = command
        self.subcommand = subcommand
        
    #--------------------------------------------------------------------------
    
    def set_data(self, data):
        self.data = data
        self.calculate_size()
        
    #--------------------------------------------------------------------------
    # Set total transmission size for packet types that need it
    def set_totalsize(self, totalsize):
        self.totalsize = totalsize
        self.calculate_checksum()
    
    #--------------------------------------------------------------------------
    # Set packet index for packet types that need it
    def set_index(self, index):
        self.index = index
        self.calculate_checksum()
    
    #--------------------------------------------------------------------------
    
    # Calculate byte size of the packet.
    # Always includes size bytes (2) and command/subcommand bytes (2).
    # Depending on the subcommand, there may be a payload.
    def calculate_size(self):
        # Start packet has two payloads: total size of the
        # upload (4 bytes) and the gallery index (1 byte)
        if self.subcommand == PixooMaxGalleryUpload.CMD_UPLOAD_SUB_START:
            self.size = 9
            
        # Data packets have a more complex payload:
        # They include at least the size (2 bytes), command/subcommand (2 bytes),
        # the total upload size (4 bytes), a packet index (2 bytes)
        # and a variable-size data block.
        if self.subcommand == PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA:
            self.size = 10+len(self.data)
        # End packet has no payload
        if self.subcommand == PixooMaxGalleryUpload.CMD_UPLOAD_SUB_END:
            self.size = 4
            
        self.calculate_checksum()
    #--------------------------------------------------------------------------
    
    # Calculate packet checksum based on hex byte representation.
    # Includes command, subcommand, data size and data.
    def calculate_checksum(self):
        args = [self.size&0xff, (self.size>>8)&0xff, self.command&0xff, self.subcommand&0xff]
        #print("args:", args)
        tsize = []
        if self.subcommand&0xff in [PixooMaxGalleryUpload.CMD_UPLOAD_SUB_START, PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA]:
            byte0 = self.totalsize & 0xff
            byte1 = (self.totalsize >> 8) & 0xff
            byte2 = (self.totalsize >> 16) & 0xff
            byte3 = (self.totalsize >> 24) & 0xff
            tsize = [byte0, byte1, byte2, byte3]
        
        index = []
        if self.subcommand&0xff in [PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA]:
            index = [self.index&0xff, (self.index>>8)&0xff]
        
        args = args+tsize+index+self.data
        #args = args+self.data
        self.checksum = sum(args)
        
    #--------------------------------------------------------------------------
    
    def get(self):
        # prepare entire packet
        result = [self.PACKET_START]
        result = result + [self.size&0xff, (self.size>>8)&0xff, self.command&0xff, self.subcommand&0xff]
        
        if self.subcommand in [PixooMaxGalleryUpload.CMD_UPLOAD_SUB_START, PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA]:
            byte0 = self.totalsize & 0xff
            byte1 = (self.totalsize >> 8) & 0xff
            byte2 = (self.totalsize >> 16) & 0xff
            byte3 = (self.totalsize >> 24) & 0xff
            result = result + [byte0, byte1, byte2, byte3]
            
        if self.subcommand in [PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA]:
            byte0 = self.index & 0xff
            byte1 = (self.index >> 8) & 0xff
            result = result + [byte0, byte1]
        
        if self.subcommand in [PixooMaxGalleryUpload.CMD_UPLOAD_SUB_START, PixooMaxGalleryUpload.CMD_UPLOAD_SUB_DATA]:
            result = result + self.data
            #result = result + [0]
        
        cs_byte0 = self.checksum & 0xff
        cs_byte1 = (self.checksum >> 8) & 0xff
        result = result + [cs_byte0, cs_byte1]
        result = result + [self.PACKET_END]
        return result
    
    #--------------------------------------------------------------------------
    
    def debug(self):
        print(vars(self))
    
#===================================================================

class PixooMaxImage:
    PALTYPE_FULL = 0x03
    PALTYPE_DIFF = 0x04
    
    imagedata = []
    chunks = []
    
    #--------------------------------------------------------------------------
    def __init__(self, filepath, index):
        #print("--- image init:", filepath, "at index", index)
        self.imagedata = self.prepare(filepath, index)
        #print("...added with size:", self.size())
        #self.print_hex()
        #print("--- image init done\n")
    
    #--------------------------------------------------------------------------
    # Get imagedata as list of bytes.
    def get(self):
        return self.imagedata
        
    #--------------------------------------------------------------------------
    # Get imagedata as list of bytes.
    def print_imagedata(self):
        if self.imagedata:
            for image in self.imagedata:
                print("\n-------------\n", image)
        
    #--------------------------------------------------------------------------
    # Print imagedata as hex string, for debugging.
    def print_hex(self):
        if self.imagedata:
            for img in self.imagedata:
                result = ""
                for byte in img:
                    result = result + "%0.2X" % byte
                print(result)
    
    #--------------------------------------------------------------------------
    # return size of all image data
    def size(self):
        result = 0
        for img in self.imagedata:
            result = result+len(img)
        return result
    
    #--------------------------------------------------------------------------
    def prepare(self, filepath, image_index):
        """
        Parse image file and prepare it for uploading to device. Supports both single images and animated GIFs. Speed is in milliseconds.
        """
        frames = []
        # Add some metadata info to the beginning of the entire animation. Meaning not clear yet.
        metaframe1 = [0xAA, 0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00]
        metaframe2 = [0xAA, 0x09, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]
        frames.append(metaframe1)
        frames.append(metaframe2)
        
        img = Image.open(filepath)
        
        # The Pixoo-Max distinguishes separate images/animations in a gallery by the lower digit of the
        # duration byte - successing images must have different numbers, otherwise looping won't work.
        duration = 500+(image_index%1)
        
        # The Pixoo-Max doesn't support variable-duration GIFs and displays each frame for a fixed time instead.
        # To fix this, we're setting a fixed playback speed, but multiply the actual frames based on
        # their duration. Of course this only allows for multiples of the shortest frame duration.
        # First, we need to find out the duration of all animation frames, then determine the shortest
        # frame and then calculate a duration factor for each of the other frames.
        enable_duration_factor = True
        durations = []
        for n in range(img.n_frames):
            img.seek(n)
            if 'duration' in img.info:
                durations.append(img.info['duration']+(image_index%1))
                
                # switch to fixed duration for debugging
                #durations.append(duration)
            else:
                durations.append(duration)

        # Find the shortest frame duration but keep in mind that
        # Pixoo's fastest playback is 25ms per frame
        shortest_duration = max(25, min(durations))
        
        previous_palette = []
        firstframe = True
        for n in range(img.n_frames):
            img.seek(n)
            
            # calculate duration factor for current frame
            current_duration = durations[n]
            
            if enable_duration_factor:
                duration_factor = round(current_duration/shortest_duration)
                current_duration = shortest_duration
                #print("Frame", n,"duration factor is", duration_factor)
            else:
                duration_factor = 1
            #print("Frame", n, "duration is", current_duration)
            
            num_colors, encodedpalette, pixel_data, num_new_colors = self.encode_raw_image(img.convert(mode='RGB'))
            
            #print("num_colors:", num_colors)
            #print("encodedpalette:", encodedpalette)
            #print("num_new_colors:", num_new_colors)
            #print("previous_palette:", previous_palette)
            
            # wrap num_colors around to 0 when all 256 colors are used
            # Only needed for the Pixoo, because it only had 1 byte for the number of colors.
            # The Pixoo-Max has two bytes!
            #num_colors = num_colors % 256
            
            frame_size = 8 + len(pixel_data) + len(encodedpalette)

            # A Pixoo-Max packet has a maximum size of 266, which includes 10 bytes of SPP frame header and a maximum
            # of 256 bytes of image data. The packet size field will also report the correct size, unlike
            # the size field of an image data block, which will always report the size of the entire animation frame,
            # un-chunked. If any data is cut off, it will be continued in the next SPP frame,
            # immediately after the header.

            frame_header = [0xAA, frame_size&0xff, (frame_size>>8)&0xff, current_duration&0xff, (current_duration>>8)&0xff, self.PALTYPE_FULL, num_colors & 0xff, (num_colors >> 8) & 0xff]
            
            frame = frame_header + encodedpalette + pixel_data
            frames.append(frame*duration_factor)
            
        #frames = metaframe1+metaframe2+frames
        return frames
        
    #--------------------------------------------------------------------------        
    def encode_raw_image(self, img):
        """
        Encode a 32x32 image.
        """
        # ensure image is 32x32
        w,h = img.size
        if w == h:
            # resize if image is too big
            if w != 32:
                img = img.resize((32,32))

            # create palette and pixel array
            pixels = []
            
            palette = []
            
            for y in range(32):
                for x in range(32):
                    pix = img.getpixel((x,y))
                    if isinstance(pix, int):
                        pix = [pix, pix, pix]
                        
                    if len(pix) == 4:
                        r,g,b,a = pix
                    elif len(pix) == 3:
                        r,g,b = pix
                    if (r,g,b) not in palette:
                        palette.append((r,g,b))
                        idx = len(palette)-1
                    else:
                        idx = palette.index((r,g,b))
                    pixels.append(idx)
            num_new_colors = len(palette)
            
            # encode pixels
            bitwidth = ceil(log10(len(palette))/log10(2))
            nbytes = ceil((256*bitwidth)/8.)
            encoded_pixels = [0]*nbytes

            encoded_pixels = []
            encoded_byte = ''
            for i in pixels:
                encoded_byte = bin(i)[2:].rjust(bitwidth, '0') + encoded_byte
            while len(encoded_byte) >= 8:
                encoded_pixels.append(encoded_byte[-8:])
                encoded_byte = encoded_byte[:-8]
                
            # Padding never observed in actual transmissions
            #padding = 8-len(encoded_byte)
            #encoded_pixels.append(encoded_byte.rjust(bitwidth, '0'))
            
            encoded_data = [int(c, 2) for c in encoded_pixels]
            encoded_palette = []
            for r,g,b in palette:
                encoded_palette += [r,g,b]
            returndata = (int(len(encoded_palette)/3), encoded_palette, encoded_data, num_new_colors)
            return returndata
        else:
            print('Error: Image has non-square size.')

#===================================================================

def print_usage():
    print("\nUsage: %s <Pixoo-Max BT address> <command> <argument(s)>" % sys.argv[0])
    print("\ncommands:")
    print("\tupload <gallery index> <list of files to upload>")
    print("\t\t- upload list of files to gallery 1, 2 or 3.")
    print("\t\t- example: 'upload 1 \"file1.gif\" \"file2.gif\"'")
    print("\tdeletegallery <gallery index>")
    print("\t\t- delete all data in gallery 1, 2 or 3 - use this to fix corrupted galleries or for a fresh start.")
    print("\t\t- example: 'deletegallery 1'")

#===================================================================

if __name__ == '__main__':
    
    print("\nPixoo-Max Gallery Uploader v0.1 by Thomas Radeke, 2025")
    print("https://github.com/ThomasRadeke/pixoomax-upload\n")
    if len(sys.argv) >= 2:
        pixoo_baddr = sys.argv[1]
        pixoo_baddr = pixoo_baddr.replace("-", ":")
        
        # check if the address is a valid MAC address
        mac_regex = re.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
        if not mac_regex.match(pixoo_baddr):
            print("Error: That's not a valid MAC address.")
            print_usage()
            sys.exit()
        
        pixoomax = PixooMaxGalleryUpload(pixoo_baddr)
        
        command = None
        argument = None
        
        if(len(sys.argv) >=3):
            command = sys.argv[2]

        if command == 'upload':
            arguments = sys.argv[3:]
            
            if len(arguments) > 0:
                if arguments[0].isdigit() and int(arguments[0]) in (1,2,3):
                    gallery_index = int(arguments[0])-1
                    pixoomax.set_gallery_index(gallery_index)
                    files = arguments[1:]
                    if(len(files) > 0):
                        for file in files:
                            file = file.rstrip()
                            if os.path.isfile(file):
                                pixoomax.add(file)
                            else:
                                print("Warning: file doesn't exist - skipping:", file)
                    else:
                        print("Error: no files given.")
                        print_usage()
                        sys.exit()
                else:
                    print("Error: gallery index can only be 1, 2 or 3.")
                    print_usage()
                    sys.exit()
                
            else:
                print("Error: no gallery index or files given.")
                print_usage()
                sys.exit()
            
            # TODO: add a file size check. The Pixoo-Max has a considerably larger storage than
            # the Pixoo, but still, uploading too much stuff creates corruption and can lead to the
            # Pixoo-Max not reacting anymore. In this case, use the "deletegallery" command
            # for a fresh start.
            
            validfiles = pixoomax.get_images()
            if len(validfiles) > 0:
                
                print("Connecting to Pixoo-Max...")
                pixoomax.connect()
                
                if len(validfiles) > 17:
                    print("\nWARNING: The Pixoo-Max only supports up to 17 images or animations per gallery. The following files will NOT be uploaded:")
                    for f in validfiles[17:]:
                        print(f)
                    print("\n")
                print("Uploading {} images to gallery {}...".format(len(validfiles), gallery_index+1))
                pixoomax.do_upload()
            else:
                print("Error: ended up without valid files. Check your paths.")
                print_usage()
                sys.exit()

        elif command == 'deletegallery':
            if len(sys.argv) >= 4 and sys.argv[3].isdigit():
                argument = sys.argv[3]
                if int(argument) in (1,2,3):
                    print("Connecting to Pixoo-Max...")
                    pixoomax.connect()
                    print("Deleting gallery {}...".format(argument))
                    pixoomax.delete_gallery(int(argument)-1)
                    print("Done.")
                else:
                    print("Error: invalid gallery index. Pixoo-Max only has galleries 1, 2 and 3.")
                    print_usage()
                    sys.exit()
            else:
                print("Error: no gallery index given.")
                print_usage()
                sys.exit()
            
        
        else:
            print("Error: no command given. What do you want me to do?")
            print_usage()
            sys.exit()
                
    else:
        print_usage()
