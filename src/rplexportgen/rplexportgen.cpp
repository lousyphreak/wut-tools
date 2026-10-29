#include "utils.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <functional>
#include <fstream>
#include <locale>
#include <vector>
#include <string>
#include <zlib.h>

/*
.extern __preinit_user

.section .fexports, "", @0x80000001
.align 4

.long 1
.long 0x13371337

.long __preinit_user
.long 0x10

.string "__preinit_user"
.byte 0
 */

enum class ReadMode
{
   INVALID,
   TEXT,
   DATA,
   TLS,
   NAME
};

void
writeExports(std::ofstream &out,
             bool isData,
             const std::vector<std::string> &exports,
             bool host = false)
{
   // Calculate signature
   uint32_t signature = crc32(0, Z_NULL, 0);
   for (const auto &name : exports) {
      signature = crc32(signature, reinterpret_cast<const Bytef *>(name.data()), name.size() + 1);
   }

   // Write out .extern to declare the symbols
   for (const auto &name : exports) {
      out << ".extern " << name << std::endl;
   }
   out << std::endl;

   // Write out header
   if (isData) {
      out << ".section .dexports, \"a\", @0x80000001" << std::endl;
   } else {
      out << ".section .fexports, \"ax\", @0x80000001" << std::endl;
   }

   out << ".align 4" << std::endl;
   out << std::endl;
   if (host) {
      out << ".global __wut_rpx_exports\n__wut_rpx_exports:\n";
   }

   out << ".long " << std::dec << exports.size() << std::endl;
   out << ".long 0x" << std::hex << signature << std::endl;
   out << std::endl;

   // Write out each export
   auto nameOffset = 8 + 8 * exports.size();
   for (const auto &name : exports) {
      out << ".long " << name << std::endl;
      out << ".long 0x" << std::hex << nameOffset << std::endl;
      nameOffset += name.size() + 1;
   }
   out << std::endl;

   // Write out the strings
   for (const auto &name : exports) {
      out << ".string \"" << name << "\"" << std::endl;
      nameOffset += name.size() + 1;
   }
   out << std::endl;
}

int main(int argc, char **argv)
{
   std::vector<std::string> funcExports, dataExports, tlsExports;
   ReadMode readMode = ReadMode::INVALID;
   bool host = argc > 1 && std::string(argv[1]) == "--host";
   if (host) { --argc; ++argv; }

   if (argc < 3) {
      std::cout << "rplexportgen [--host] <exports.def> <output.S>" << std::endl;
      return 0;
   }

   {
      std::ifstream in;
      in.open(argv[1]);

      if (!in.is_open()) {
         std::cout << "Could not open file " << argv[1] << " for reading" << std::endl;
         return -1;
      }

      std::string line;
      while (std::getline(in, line)) {
         // Trim comments
         std::size_t commentOffset = line.find("//");
         if (commentOffset != std::string::npos) {
            line = line.substr(0, commentOffset);
         }

         // Trim whitespace
         line = trim(line);

         // Skip blank lines
         if (line.length() == 0) {
            continue;
         }

         // Look for section headers
         if (line[0] == ':') {
            if (line.substr(1) == "TEXT") {
               readMode = ReadMode::TEXT;
            } else if (line.substr(1) == "DATA") {
               readMode = ReadMode::DATA;
            } else if (host && line.substr(1) == "TLS") {
               readMode = ReadMode::TLS;
            } else if (line.substr(1, 4) == "NAME") {
               readMode = ReadMode::NAME;
            } else {
               std::cout << "Unexpected section type" << std::endl;
               return -1;
            }
            continue;
         }

         if (readMode == ReadMode::TEXT) {
            funcExports.push_back(host && line == "atexit" ? "__cxa_atexit" : line);
         } else if (readMode == ReadMode::DATA) {
            dataExports.push_back(line);
         } else if (readMode == ReadMode::TLS) {
            tlsExports.push_back(line);
            dataExports.push_back("__wut_tls_" + line);
         } else if (readMode == ReadMode::NAME) {
            // We can ignore name in rplexportgen
         } else {
            std::cout << "Unexpected section data" << std::endl;
            return -1;
         }
      }
   }

   if (host) {
      funcExports.push_back("__preinit_user");
      funcExports.push_back("__wut_bind_imports_v1");
   }

   // Exports must be in alphabetical order because loader.elf uses binary search
   std::sort(funcExports.begin(), funcExports.end());
   std::sort(dataExports.begin(), dataExports.end());
   if (host) funcExports.erase(std::unique(funcExports.begin(), funcExports.end()), funcExports.end());

   {
      std::ofstream out;
      out.open(argv[2]);

      if (!out.is_open()) {
         std::cout << "Could not open file " << argv[2] << " for writing" << std::endl;
         return -1;
      }

      if (funcExports.size() > 0) {
         writeExports(out, false, funcExports, host);
      }

      if (dataExports.size() > 0) {
         writeExports(out, true, dataExports);
      }

      for (const auto &name : tlsExports) {
         out << ".extern " << name << "\n.type " << name << ", @tls_object\n"
             << ".section .data.wut_tls_exports, \"aw\", @progbits\n.balign 4\n"
             << ".global __wut_tls_" << name << "\n.type __wut_tls_" << name << ", @object\n"
             << "__wut_tls_" << name << ":\n.long 0\n.long 0\n"
             << ".reloc __wut_tls_" << name << ", R_PPC_DTPMOD32, " << name << "\n"
             << ".reloc __wut_tls_" << name << "+4, R_PPC_DTPREL32, " << name << "\n";
      }
   }

   return 0;
}
