// std
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// stdc++
#include <string>
#include <map>

// iconv
#include <iconv.h>

// json
#include <json.hpp>

// unix-ish
#include <unistd.h>
#include <fcntl.h>

using json = nlohmann::json;

// see https://github.com/djey47/tduf-next/tree/master/doc/RE/xmb
// take extra care with endian conversion when using this source file in big endian systems

int write_data(int fd, const char *buffer, int len){
	int bytes_written = 0;
	while(bytes_written < len){
		int loop_written = write(fd, &buffer[bytes_written], len - bytes_written);
		if(loop_written < 0){
			return loop_written;
		}
		bytes_written += loop_written;
	}
	return bytes_written;
}

int log_fd = -1;
#define LOG(...){ \
	printf(__VA_ARGS__); \
	if(log_fd >= 0){ \
		char _log_buffer[1024]; \
		int _log_len = sprintf(_log_buffer, __VA_ARGS__); \
		write_data(log_fd, _log_buffer, _log_len); \
	} \
}

void print_usage(const char* path){
	LOG("%s <path to xmb or json file>\n");
}

int read_data(int fd, char *buffer, int len){
	int bytes_read = 0;
	while(bytes_read < len){
		int loop_read = read(fd, &buffer[bytes_read], len - bytes_read);
		if(loop_read < 0){
			return loop_read;
		}
		bytes_read += loop_read;
	}
	return bytes_read;
}

struct __attribute__((packed)) xmb_header{
	char tag[4];
	uint32_t maybe_version;
	uint32_t descriptor_table_address;
	uint32_t metadata_address;
	uint32_t subobject_data_table_address;
	uint32_t root_key_name_offset;
	uint32_t number_of_types_times_2;
};

struct __attribute__((packed)) metadata_header{
	uint32_t type_information;
	uint32_t name_offset;
};

// what does the "array" type mean, if array is denoted on child_metadata/key definition?
struct __attribute__((packed)) object_key_header{
	uint32_t name_offset;
	uint8_t metadata_offset;
	uint16_t padding;
	uint8_t array_marker;
};

struct __attribute__((packed)) array_description{
	uint32_t array_length;
	uint32_t array_start_offset;
};

struct child_metadata{
	uint32_t name_offset;
	uint32_t metadata_offset;
	bool is_array;
};

struct metadata {
	uint32_t type;
	bool is_root;
	uint32_t name_offset;
	uint32_t order;
	std::vector<struct child_metadata> children;
};


int iso_8859_2_to_utf8(const char *in_buf, int in_buf_size, char *out_buf, int out_buf_size){
	// if it blows up welp
	iconv_t cd = iconv_open("UTF8", "ISO_8859-2");
	const char* in_buf_ref = in_buf;
	char* out_buf_ref = out_buf;
	size_t in_bytes_left = in_buf_size;
	size_t out_bytes_left = out_buf_size;
	#ifdef O_BINARY
	int ret = iconv(cd, (const char **)&in_buf_ref, &in_bytes_left, &out_buf_ref, &out_bytes_left);
	#else
	int ret = iconv(cd, (char **)&in_buf_ref, &in_bytes_left, &out_buf_ref, &out_bytes_left);
	#endif
	if(ret != 0){
		return -1;
	}
	iconv_close(cd);
	return ((uint64_t)out_buf_ref) - ((uint64_t)out_buf);
}

struct type_description{
	std::string name;
	uint32_t size;
	uint32_t code;
};

std::map<uint32_t, struct type_description> type_code_to_description_map;
std::map<std::string, struct type_description> type_string_to_description_map;

void init_type_maps(){
	type_code_to_description_map[0] = {.name = "object", .size = 0, .code = 0};
	type_code_to_description_map[1] = {.name = "bool", .size = 1, .code = 1};
	type_code_to_description_map[2] = {.name = "sint8", .size = 1, .code = 2};
	type_code_to_description_map[3] = {.name = "sint16", .size = 2, .code = 3};
	type_code_to_description_map[4] = {.name = "sint32", .size = 4, .code = 4};
	type_code_to_description_map[5] = {.name = "sint64", .size = 8, .code = 5};
	type_code_to_description_map[6] = {.name = "uint8", .size = 1, .code = 6};
	type_code_to_description_map[7] = {.name = "uint16", .size = 2, .code = 7};
	type_code_to_description_map[8] = {.name = "uint32", .size = 4, .code = 8};
	type_code_to_description_map[9] = {.name = "uint64", .size = 8, .code = 9};
	type_code_to_description_map[10] = {.name = "float", .size = 4, .code = 10};
	type_code_to_description_map[11] = {.name = "double", .size = 8, .code = 11};
	type_code_to_description_map[12] = {.name = "string", .size = 0, .code = 12};

	// seriously what is an array
	type_code_to_description_map[13] = {.name = "array", .size = 0, .code = 13};

	for(int i = 0; i < type_code_to_description_map.size();i++){
		type_string_to_description_map[type_code_to_description_map[i].name] = type_code_to_description_map[0];
	}
}

uint32_t read_data_section(const char *buffer, int buffer_len, uint32_t read_head, uint32_t type, json &value_out, uint32_t subobject_data_table_address){
	if(type == 13){
		LOG("type array found during data read, huh\n");
		exit(1);
	}
	uint32_t size = type_code_to_description_map[type].size;

	if(read_head + size > buffer_len){
		LOG("end of file reached while reading data, read head 0x%08x, file size 0x%08x, size to read %d\n", read_head, buffer_len, size);
		exit(1);
	}

	switch(type){
		case 1:{
			uint8_t value;
			value = buffer[read_head];
			read_head++;
			value_out = value? true: false;
			LOG("value: offset 0x%08x, bool %s\n", read_head - 1, value? "true": "false");
			break;
		}
		case 2:{
			int8_t value;
			value = buffer[read_head];
			read_head++;
			value_out = value;
			LOG("value: offset 0x%08x, int8 %d\n", read_head - 1, value);
			break;
		}
		case 3:{
			int16_t value;
			memcpy(&value, &buffer[read_head], 2);
			read_head += 2;
			value_out = value;
			LOG("value: offset 0x%08x, int16 %d\n", read_head - 2, value);
			break;
		}
		case 4:{
			int32_t value;
			memcpy(&value, &buffer[read_head], 4);
			read_head += 4;
			value_out = value;
			LOG("value: offset 0x%08x, int32 %d\n", read_head - 4, value);
			break;
		}
		case 5:{
			int64_t value;
			memcpy(&value, &buffer[read_head], 8);
			read_head += 8;
			value_out = value;
			LOG("value: offset 0x%08x, int32 %lld\n", read_head - 8, value);
			break;
		}
		case 6:{
			uint8_t value;
			value = buffer[read_head];
			read_head++;
			value_out = value;
			LOG("value: offset 0x%08x, uint8 0x%02x\n", read_head - 1, value);
			break;
		}
		case 7:{
			uint16_t value;
			memcpy(&value, &buffer[read_head], 2);
			read_head += 2;
			value_out = value;
			LOG("value: offset 0x%08x, uint16 0x%04x\n", read_head - 2, value);
			break;
		}
		case 8:{
			uint32_t value;
			memcpy(&value, &buffer[read_head], 4);
			read_head += 4;
			value_out = value;
			LOG("value: offset 0x%08x, uint32 0x%08x\n", read_head - 4, value);
			break;
		}
		case 9:{
			uint64_t value;
			memcpy(&value, &buffer[read_head], 8);
			read_head += 8;
			value_out = value;
			LOG("value: offset 0x%08x, uint64 0x%08x\n", read_head - 8, value);
			break;
		}
		case 10:{
			float value;
			memcpy(&value, &buffer[read_head], 4);
			read_head += 4;
			value_out = value;
			LOG("value: offset 0x%08x, float %f\n", read_head - 4, value);
			break;
		}
		case 11:{
			double value;
			memcpy(&value, &buffer[read_head], 8);
			read_head += 8;
			value_out = value;
			LOG("value: offset 0x%08x, double %f\n", read_head - 8, value);
			break;
		}
		case 12:{
			char string_buffer[4096];
			int len = 0;
			uint32_t offset;
			if(read_head + 4 > buffer_len){
				LOG("end of file reached while trying to read string offset\n");
				exit(1);
			}
			memcpy(&offset, &buffer[read_head], 4);
			read_head += 4;
			uint32_t string_read_head = subobject_data_table_address + offset;
			while(true){
				if(len + 1 > sizeof(string_buffer)){
					LOG("string is too big. wow\n");
					exit(1);
				}
				if(string_read_head + 1 > buffer_len){
					LOG("end of file reached while reading string\n");
					exit(1);
				}
				string_buffer[len] = buffer[string_read_head];
				len++;
				string_read_head++;
				if(string_buffer[len - 1] == '\0'){
					char decode_buffer[8192];
					int decoded_size = iso_8859_2_to_utf8(string_buffer, len, decode_buffer, sizeof(decode_buffer));
					if(decoded_size < 0){
						LOG("failed decoding data string, %d\n", decoded_size);
						exit(1);
					}
					std::string decoded_string(decode_buffer, decoded_size);
					value_out = decoded_string;
					LOG("value: offset 0x%08x, string %s\n", subobject_data_table_address + offset, decoded_string.c_str());
					break;
				}
			}
			break;
		}
	}

	return read_head;
}

uint32_t walk_object(const char *buffer, int buffer_len, uint32_t read_head, json &current_node, const struct metadata &object_metadata, std::map<uint32_t, std::string> &offset_tag_name_map, std::map<uint32_t, struct metadata> offset_metadata_map, uint32_t subobject_data_table_address){
	for(int i = 0;i < object_metadata.children.size();i++){
		const struct child_metadata &child = object_metadata.children[i];
		json object;
		if(!offset_tag_name_map.contains(child.name_offset)){
			LOG("unknown name offset 0x%08x while walking object children\n", child.name_offset);
			exit(1);
		}
		std::string tagname = offset_tag_name_map[child.name_offset];
		object["name"] = tagname;
		if(!offset_metadata_map.contains(child.metadata_offset)){
			LOG("unknown metadata offset 0x%08x while walking object children\n", child.metadata_offset);
			exit(1);
		}
		const struct metadata &object_child_metadata = offset_metadata_map[child.metadata_offset];
		std::string object_child_metadata_name = offset_tag_name_map[object_child_metadata.name_offset];
		bool is_virtual_class = memcmp(object_child_metadata_name.c_str(), "AUTOGEN_CLASS_", 14) == 0;

		if(!type_code_to_description_map.contains(object_child_metadata.type) && !is_virtual_class){
			LOG("unknown type %d, aborting\n", object_child_metadata.type);
			exit(1);
		}
		if(is_virtual_class){
			object["type"] = "virtual class";
		}else{
			object["type"] = type_code_to_description_map[object_child_metadata.type].name;
		}
		LOG("class child: name offset 0x%08x, name %s, metadata offset 0x%08x, metadata name %s, is array %s\n", child.name_offset, tagname.c_str(), child.metadata_offset, object_child_metadata_name.c_str(), child.is_array? "true": "false");
		if(child.is_array){
			if(read_head + sizeof(struct array_description) > buffer_len){
				LOG("reached end of file reading array description\n");
				exit(1);
			}
			struct array_description *ades = (struct array_description *)&buffer[read_head];
			read_head += sizeof(struct array_description);
			uint32_t array_read_head = subobject_data_table_address + ades->array_start_offset;
			for(uint32_t j = 0;j < ades->array_length;j++){
				json array_entry;
				if(object_child_metadata.type == 0 || is_virtual_class){
					array_read_head = walk_object(buffer, buffer_len, array_read_head, array_entry, object_child_metadata, offset_tag_name_map, offset_metadata_map, subobject_data_table_address);
				}else{
					array_read_head = read_data_section(buffer, buffer_len, array_read_head, object_child_metadata.type, array_entry, subobject_data_table_address);
				}
				object["value"].push_back(array_entry);
			}
		}else{
			json value;
			if(object_child_metadata.type == 0 || is_virtual_class){
				read_head = walk_object(buffer, buffer_len, read_head, value, object_child_metadata, offset_tag_name_map, offset_metadata_map, subobject_data_table_address);
			}else{
				read_head = read_data_section(buffer, buffer_len, read_head, object_child_metadata.type, value, subobject_data_table_address);
			}
			object["value"] = value;
		}

		current_node["children"].push_back(object);
	}
	return read_head;
}

void decode(const char *file_path, const char *buffer, int buffer_len){
	if(sizeof(xmb_header) > buffer_len){
		LOG("file is smaller than xmb header, size: %d\n", buffer_len);
		exit(1);
	}
	struct xmb_header *header = (struct xmb_header *)buffer;
	json output;
	char name_buffer_raw[128];
	char name_buffer_conv[512];
	uint32_t read_head = header->descriptor_table_address;

	LOG("xmbf header: version 0x%08x, descriptor table address 0x%08x, metadata address 0x%08x, data address 0x%08x, root key name offset 0x%08x, number of types * 2 %d\n", header->maybe_version, header->descriptor_table_address, header->metadata_address, header->subobject_data_table_address, header->root_key_name_offset, header->number_of_types_times_2);

	// map and store all the tag names
	std::map<uint32_t, std::string> offset_tag_name_map;
	while(true){
		uint32_t descriptor_table_name_offset = read_head - header->descriptor_table_address;
		for(int i = 0;true;i++){
			if(read_head >= buffer_len){
				LOG("reached end of file while gathering type names\n");
				exit(1);
			}
			if(i >= sizeof(name_buffer_raw)){
				LOG("reached end of raw buffer while gather type names\n");
				exit(1);
			}
			if(read_head == header->metadata_address){
				// reached the end of descriptor table before reaching '\0', probably just read some padding
				// of all things they used 'A' for padding..?
				break;
			}
			name_buffer_raw[i] = buffer[read_head];
			read_head++;
			if(name_buffer_raw[i] == '\0'){
				int converted_len = iso_8859_2_to_utf8(name_buffer_raw, i, name_buffer_conv, sizeof(name_buffer_conv));
				if(converted_len < 0){
					LOG("failed converting ");
					for(int j = 0;j < i; j++){
						LOG("0x%02x ", name_buffer_raw[j]);
					}
					LOG(" to UTF8\n");
					exit(1);
				}
				std::string tag_name(name_buffer_conv, converted_len);
				offset_tag_name_map[descriptor_table_name_offset] = tag_name;
				LOG("descriptor: offset 0x%08x, %s\n", descriptor_table_name_offset, tag_name.c_str());
				break;
			}
		}
		if(read_head == header->metadata_address){
			break;
		}
	}

	std::map<uint32_t, struct metadata> offset_metadata_map;
	std::vector<uint32_t> metadata_offset_list;
	// walk all meta data
	read_head = header->metadata_address;
	for(int i = 0;i < header->number_of_types_times_2 / 2; i++){
		// number of types seems to not be what is claimed
		if(read_head == header->subobject_data_table_address){
			break;
		}
		uint32_t metadata_offset = read_head - header->metadata_address;
		if(read_head + sizeof(struct metadata_header) > buffer_len){
			LOG("reached end of file while reading metadata header\n");
			exit(1);
		}
		struct metadata_header *mheader = (struct metadata_header *)&buffer[read_head];
		read_head += sizeof(struct metadata_header);
		uint32_t type = mheader->type_information & 0xff;
		uint32_t private_type_info = mheader->type_information >> 0x10;
		if(!offset_tag_name_map.contains(mheader->name_offset)){
			LOG("we're not reading the metadata section right, name offset 0x%08x not found, metadata at file offset 0x%08x\n", mheader->name_offset, read_head - sizeof(struct metadata_header));
			exit(1);
		}
		std::string tagname = offset_tag_name_map[mheader->name_offset];

		offset_metadata_map[metadata_offset] = {
			.type = type,
			.is_root = mheader->name_offset == header->root_key_name_offset,
			.name_offset = mheader->name_offset,
			.order = (uint32_t)i,
			.children = {}
		};
		metadata_offset_list.push_back(metadata_offset);

		if(type == 0 || memcmp(tagname.c_str(), "AUTOGEN_CLASS_", 14) == 0){
			int num_children = (mheader->type_information >> 4) & 0x7ff;
			if(num_children <= 0){
				LOG("object metadata at %d has %d children, aborting\n", read_head - sizeof(struct metadata_header), num_children);
				exit(1);
			}
			for(int j = 0; j < num_children; j++){
				if(read_head + sizeof(struct object_key_header) > buffer_len){
					LOG("reached end of file while parsing object keys\n");
					exit(1);
				}
				struct object_key_header *okheader = (struct object_key_header *)&buffer[read_head];
				read_head += sizeof(struct object_key_header);
				if(!offset_tag_name_map.contains(okheader->name_offset)){
					LOG("we're not reading the child metadata section right, name offset 0x%08x not found\n", okheader->name_offset);
					exit(1);
				}
				offset_metadata_map[metadata_offset].children.push_back({
					.name_offset = okheader->name_offset,
					.metadata_offset = (uint32_t)(okheader->metadata_offset * 4),
					.is_array = (okheader->array_marker == 0x80)
				});
			}
		}

		LOG("metadata: offset 0x%08x, type %d, name offset 0x%08x, name %s, is root %s, child count %d\n", metadata_offset, type, mheader->name_offset, tagname.c_str(), offset_metadata_map[metadata_offset].is_root? "true": "false", offset_metadata_map[metadata_offset].children.size());
		for(int j = 0;j < offset_metadata_map[metadata_offset].children.size(); j++){
			const struct child_metadata &child = offset_metadata_map[metadata_offset].children[j];
			std::string child_tagname = offset_tag_name_map[child.name_offset];
			LOG("child_metadata: name offset 0x%08x, name %s, metadata offset 0x%08x, is array %s\n", child.name_offset, child_tagname.c_str(), child.metadata_offset, child.is_array? "true": "false");
		}
	}

	// start decoding from the last metadata, that is so far the virtual class of root
	read_head = header->subobject_data_table_address;
	if(!offset_tag_name_map.contains(header->root_key_name_offset)){
		LOG("root key name with offset 0x%08x not found\n", header->root_key_name_offset);
		exit(1);
	}
	output["root_name"] = offset_tag_name_map[header->root_key_name_offset];

	json virtual_class;
	const struct metadata &mdata = offset_metadata_map[metadata_offset_list[metadata_offset_list.size() - 1]];
	std::string tagname = offset_tag_name_map[mdata.name_offset];
	LOG("root virtual class: name %s\n", tagname.c_str());
	read_head = walk_object(buffer, buffer_len, read_head, virtual_class, mdata, offset_tag_name_map, offset_metadata_map, header->subobject_data_table_address);
	output["children"].push_back(virtual_class);

	// haven't quite decide the json output yet
	exit(0);

	char output_path[1024];
	sprintf(output_path, "%s.json", file_path);
	#ifdef O_BINARY
	int output_fd = open(output_path, O_WRONLY | O_BINARY | O_CREAT | O_TRUNC);
	#else
	int output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC);
	#endif

	if(output_fd < 0){
		LOG("failed opening %s for writing, %d\n", output_path, output_fd);
	}
	std::string json_string = output.dump(4);
	int write_result = write_data(output_fd, json_string.c_str(), json_string.size());
	if(write_result < 0){
		LOG("failed writing json to %s, %d\n", output_path, write_result);
		exit(1);
	}
}

void encode(const char *file_path, const char *buffer, int buffer_len){
	json input;
}

int main(int argc, const char **argv){
	log_fd = open("./xmb_helper_log.txt", O_WRONLY | O_TRUNC | O_CREAT);

	if(argc != 2){
		print_usage(argv[0]);
		exit(1);
	}

	const char *file_path = argv[1];
	#ifdef O_BINARY
	int file_fd = open(file_path, O_RDONLY | O_BINARY);
	#else
	int file_fd = open(file_path, O_RDONLY);
	#endif
	if(file_fd < 0){
		LOG("failed opening %s for reading\n", file_path);
		exit(1);
	}
	int file_size = lseek(file_fd, 0, SEEK_END);
	if(file_size <= 0){
		LOG("cannot query file size, %d\n", file_size);
		exit(1);
	}
	char *buffer = (char *)malloc(file_size);
	if(buffer == NULL){
		LOG("failed allocating file buffer\n");
		exit(1);
	}
	int rewind_result = lseek(file_fd, 0, SEEK_SET);
	if(rewind_result != 0){
		LOG("failed rewinding file, %d\n", rewind_result);
		exit(1);
	}
	int bytes_read = read_data(file_fd, buffer, file_size);
	if(bytes_read != file_size){
		LOG("failed reading file, read %d bytes instead of %d\n", bytes_read, file_size);
		exit(1);
	}

	init_type_maps();

	if(memcmp("XMBF", buffer, 4) == 0){
		decode(file_path, buffer, file_size);
	}else{
		encode(file_path, buffer, file_size);
	}
	free(buffer);

	return 0;
}
