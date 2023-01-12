#include <mxml.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8 int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t
#define f32 float
#define f64 double

static const char* GetXMLAttr(mxml_node_t *node, const char *name)
{
    const char* AttrData = mxmlElementGetAttr(node, name);
    if (AttrData == NULL) AttrData = "";
    return AttrData;
}

static const char *xml_whitespace_cb(mxml_node_t *node, int where) {
    if (where == MXML_WS_AFTER_OPEN || where == MXML_WS_AFTER_CLOSE)
        return ("\n");

    return (NULL);
}

int main(int argc, char *argv[]) {
    char *input_file = argv[1]; // "text2.xml";
    char *buffer = 0;
    u64 length = 0;
    FILE *f = fopen(input_file, "rb");

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = malloc(length);
        if (buffer) {
            fread(buffer, 1, length, f);
        }
        fclose(f);
    }

    if (buffer) {
        mxml_node_t *node, *tree = NULL;
        tree = mxmlLoadString(NULL, buffer, MXML_NO_CALLBACK);

        if (!tree) {
            printf("XML: could not parse XML:\n%s\n", buffer);
            mxmlDelete(tree);
            free(buffer);
            return 1;
        }
    printf("passed: %s\n", input_file);
    return 0;
    }
    printf("File %s empty\n", input_file);
    return 1;
}
