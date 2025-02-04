#include <stdio.h>
#include <string.h>

#include "include/mime_types.h"

const char default_mime[] = "application/octet-stream";

const char * file_extension[] = {".aac", ".apng", ".arc", ".avi", ".bin", ".bmp", ".bz", ".bz2", ".css", ".csv", ".doc", ".docx",
                                ".eot", ".epub", ".gz", ".gif", ".html", ".htm", ".ico", ".jar", ".jpeg", ".jpg", ".js", ".json",
                                ".mp3", ".mp4", ".mpeg", ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".opus", ".otf", ".png", 
                                ".pdf,", ".php", ".ppt", ".pptx", ".rar",".rtf", ".sh", ".svg", ".tar", ".tiff", ".tif", ".txt", 
                                ".wav", ".weba", ".webm", ".webp", ".xhtml", ".xls", ".xlsx", ".xml", ".zip", ".7z"};

const char * mime_types[] = {
    "audio/aac",
    "image/apng",
    "application/x-freearc",
    "video/x-msvideo",
    "application/octet-stream",
    "image/bmp",
    "application/x-bzip",
    "application/x-bzip2",
    "text/css",
    "text/csv",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", //brooooo :sob:
    "application/vnd.ms-fontobject",
    "application/application/epub+zip",
    "application/gzip",
    "image/gif",
    "text/html",
    "text/html",
    "image/vnd.microsoft.icon",
    "application/java-archive",
    "image/jpeg",
    "image/jpeg",
    "text/javascript",
    "application/json",
    "audio/mpeg",
    "video/mp4",
    "video/mpeg",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.text",
    "audio/ogg",
    "video/ogg",
    "application/ogg",
    "audio/ogg",
    "font/otf",
    "image/png",
    "application/pdf",
    "application/x-httpd-php",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.rar",
    "application/rtf",
    "application/x-sh",
    "image/svg+xml",
    "application/x-tar",
    "image/tiff",
    "image/tiff",
    "text/plain",
    "audio/wav",
    "audio/webm",
    "video/webm",
    "image/webm",
    "application/xhtml+xml",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/xml",
    "application/zip",
    "application/x-7z-compressed"
};

inline const char * get_mime_type() {
    
}

const char* identify_mime_type(const char * path) {
    const char* last_slash = strrchr(path, '/');
    const char* last_dot   = strrchr(path, '.');
    if (last_slash == NULL) {
        fprintf(stderr, "Warning: file path `%s' does not contain a '/'\n", path);
        last_slash = path;
    }
    if (last_dot == NULL) {
        return default_mime;
    }
    if (last_dot > last_slash) { // file has extension, if last_dot<last_slash, there is a dot inside the path

    }
}