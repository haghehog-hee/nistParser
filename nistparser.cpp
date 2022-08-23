/*
  \file   nistparser.cpp
  \author Nikolay Moskvichev
  \date   19-apr-2015
  \brief  Разбор ANSI-NIST файлов
*/

#if 0
#define dbg0 printf
#define dbg3 printf
#define dbg7 printf
#else
#define dbg0
#define dbg3
#define dbg7 
#endif

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>


#ifdef WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#ifdef SPEX
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include <pdebugs.h>
#ifdef __cplusplus
}
#endif /* __cplusplus */
#else
#include "liba8.debugs.h"
#endif



#include "nistparser.h"

#include "pack_set1.h"
struct Type4Header
{
   unsigned len_;
   unsigned char idc_;                                              
   unsigned char imp_;                                              
   unsigned char fgp_[6];
   unsigned char isr_;
   unsigned short hll_;
   unsigned short vll_;
   unsigned char cga_;
};

struct Type7Header
{
   unsigned len_;
   unsigned char idc_;                                              
   unsigned char imt_;                                              
   unsigned char imd_;
   unsigned char pcn_[10];
   unsigned char imr_[11];
   unsigned short hll_;
   unsigned short vll_;
   unsigned char cga_;
};

struct Type8Header
{
   unsigned len_;
   unsigned char idc_;                                              
   unsigned char sig_;                                              
   unsigned char srt_;
   unsigned char isr_;
   unsigned short hll_;
   unsigned short vll_;
};


#include "pack_ret.h"

std::string fmtz(unsigned length, std::string str) 
{
    unsigned required = length - str.length();
    for (int i = 0; i < required; i++) 
    {
        str = "0" + str;
    }
    return str;
}

std::string itos(unsigned length) 
{
    std::string str = std::to_string(length);
    int length2 = length + str.length();
    std::string str2 = std::to_string(length2);
    if (str2.length() > str.length()) 
    {
        length2 += 1;
        str2 = std::to_string(length2);
    } 
    return str2;
}

nistTag::nistTag()
{
   rec_ = 0;
   nom_ = 0;
   size_ = 0;
   offset_ = 0;
   data_ = 0;
}

nistTag::~nistTag()
{
   rec_ = 0;
   nom_ = 0;
   size_ = 0;
   offset_ = 0;
   data_ = 0;
}

bool nistTag::load(const std::vector<unsigned char>& data, unsigned& offset, unsigned offset_to_record_end)
{   
   if(data.size() && offset<data.size())
   {
      unsigned offset_to_end = offset;
      //Ожидает данные в виде <номер записи>.<номер тега>:<данные><разделитель>
      unsigned dot_offset = 0;   //Смещение на разделитель между номером записи и номером тега
      unsigned colon_offset = 0; //Смещение на разделитель между номером записи и тега и данными
      for(unsigned pos=offset;pos<data.size();pos++)
      {
         //Разделитель тегов или конец записи
         if(data[pos]==nistParser::GS() || data[pos]==nistParser::FS() || (offset_to_record_end!=0 && pos==offset_to_record_end))
         {
            offset_to_end = pos;
            break;
         }
         if(data[pos]==':' && colon_offset==0)
         {
            colon_offset = pos;
            if(dot_offset)
            {
               std::vector<char> c_tag;
               c_tag.resize(colon_offset - dot_offset,0);
               memcpy(&c_tag.front(),&data.front()+dot_offset+1,colon_offset - dot_offset -1);
               //Для записей с текстовыми тегами и изображениями - изображение в последнем теге с номером 999
               if(atoi(&c_tag.front())==999) 
               {
                  offset_to_end = offset_to_record_end;
                  break;
               }
            }
         }
         if(data[pos]=='.' && dot_offset==0)
         {
            dot_offset = pos;
         }
      }

      if(dot_offset > offset &&  colon_offset > dot_offset && offset_to_end > dot_offset )
      {
         std::vector<char> c_rec;
         c_rec.resize(dot_offset-offset+1,0);
         memcpy(&c_rec.front(),&data.front()+offset,dot_offset-offset);
         rec_ = atoi(&c_rec.front());
         std::vector<char> c_tag;
         c_tag.resize(colon_offset - dot_offset,0);
         memcpy(&c_tag.front(),&data.front()+dot_offset+1,colon_offset - dot_offset -1);
         nom_ = atoi(&c_tag.front());
         offset_ = colon_offset+1;
         if(offset_to_end > offset_)
         {
            size_ = offset_to_end-offset_;
            data_ = &data.front()+offset_;
         }
         else
         {
            size_ = 0;
            data_ = 0;
         }
         offset = offset_to_end;
         dbg7( (char*)"nistTag::load record %d tag %d\n",rec_,nom_);
         return true;
      }
      else
      {
         dbg0("nistTag::load error can't find tag data beginning\n");
      }
   }
   else
   {
      dbg0("nistTag::load error invalid data\n");
   }
   return false;
}

//bool nistTag

std::vector<unsigned char> nistTag::dataCopy() const
{
   dbg7( (char*)"nistTag::dataCopy record %d tag %d\n",rec_,nom_);
   std::vector<unsigned char> res;
   if(size_)
   {
      res.resize(size_+1,0);
      memcpy(&res.front(),data_,size_);
   }
   return res;
}

nistRecord::nistRecord()
{
   offset_ = 0;
   type_ = 0;
   image_data_ = 0;
   image_data_size_ = 0;
   record_size_ = 0;
}

nistRecord::~nistRecord()
{
   clear();
}

void nistRecord::clear()
{
   offset_ = 0;
   type_ = 0;
   image_data_ = 0;
   image_data_size_ = 0;
   record_size_ = 0;
   tags_.clear();
}

bool nistRecord::load(const std::vector<unsigned char>& data, unsigned& offset,unsigned type, bool force)
{
   dbg7( (char*)"nistRecord::load record %d\n",type);
   clear();
   unsigned offset_to_end = 0;
   unsigned offset_to_start = 0;
   long record_size = 0;
   if(data.size() && offset<data.size())
   {
      offset_to_start = offset;
      if(type==1 || type==2 || type==10 || type==14 || type==15 || type==13)
      {
         nistTag new_tag;
         while(new_tag.load(data,offset,offset_to_end))
         {            
            if(new_tag.rec()!=type)
            {
               break;
               dbg0("nistRecord::load error record type %d tag record type %d\n",type,new_tag.rec());
            }
            if( new_tag.tag_no()==1) //Смещение на конец записи
            {               
               std::vector<unsigned char> tag_data;
               tag_data = new_tag.dataCopy();
               if(tag_data.size())
               {
                  record_size = atoi((char*)&tag_data.front());
               }
               if(record_size)
               {
                  offset_to_end = offset_to_start + record_size - 1; //Смещение на замыкающий разделитель, который включается в длину записи
               }
               else
               {
                  dbg0("nistRecord::load error can't get record type %d size\n",type);
                  clear();
                  return false;
               }
            }
            dbg7( (char*)"nistRecord::load record type %d tag %d loaded\n",type,new_tag.tag_no());
            tags_.push_back(new_tag);
            if(data[offset]==nistParser::FS() || (offset==offset_to_end))
            {
               type_ = type;
               offset_ = offset_to_start;
               record_size_ = offset - offset_ + 1;
               offset++;
               return true;
            }
            offset++;
         }
      }
      else
      {
         dbg0("nistRecord::load error invalid record type %d\n",type);
      }
   }
   if(force && offset_to_start!=0 && record_size!=0)
   {
      type_ = type;
      offset_ = offset_to_start;
      record_size_ = record_size;
      offset = offset_+record_size;
      return true;
   }
   else
   {
      clear();
      return false;
   }
}

int nistRecord::write(FILE* out, unsigned len)
{
    unsigned stpos = ftell(out);

    unsigned char gs;
    gs = nistParser::GS();
    unsigned char fs;
    fs = nistParser::FS();
    std::string st;
    if (len) 
    {
        st = std::to_string(type_) + ".001:" + itos(len);
    } 
    else 
    {
        st = std::to_string(type_) + ".001:";
    }
    fwrite(st.c_str(), 1, st.length(), out);
    fwrite(&gs, 1, 1, out);
    

    for (int i = 1; i < tags_.size(); i++) 
    {
        std::string number = fmtz(3, std::to_string(tags_[i].tag_no()));
        std::string str = std::to_string(type_)+"."+number+":";
        fwrite(str.c_str(), 1, str.length(), out);
        //int kek = ftell(out);
        //int diff = tags_[i].offset_ - kek;
        //std::cout << i << " " << tags_[i].tag_no() << "  " << diff << "\n";
        fwrite(tags_[i].data(), 1, tags_[i].data_size(), out);
        if (i + 1 == tags_.size()) 
        {
            if (image_data_)
            {
                fwrite(image_data_, 1, image_data_size_, out);
            }
            fwrite(&fs, 1, 1, out);
        }
        else 
        {
            fwrite(&gs, 1, 1, out);
        }
    }
    return ftell(out) - stpos;
}

//bool nistRecord::writeTag(nistTag& tag, FILE* out)
//{
//    return false;
//}


unsigned nistRecord::recordSize()
{
   dbg7( (char*)"nistRecord::recordSize record type %d size %d\n",type_,record_size_);
   return record_size_;
}

const nistTag* nistRecord::getTag(unsigned no)
{
   if(no<tagsCnt())
   {
      return &tags_[no];
   }
   return 0;
}

const nistTag* nistRecord::getTagById(unsigned id)
{
   for(unsigned tag_no = 0; tag_no<tagsCnt();tag_no++)
   {
      if(tags_[tag_no].tag_no()==id)
        return &tags_[tag_no];
   }
   return 0;

}

type1Record::type1Record()
   :nistRecord()
{
   ver_ = 0;
   priority_ = 0;
   scanning_res_ = 0.0;
   transmitting_res_ = 0.0;
}

type1Record::~type1Record()
{

}

bool type1Record::load(const std::vector<unsigned char>& data, unsigned& offset,bool force)
{
   if(nistRecord::load(data, offset,1,force))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //1.002 VER 
         tag_data = tag->dataCopy();
         ver_ = atoi((char*)&tag_data.front());
         if(ver_>0)
         {
            dbg7( (char*)"type1Record::load ver %d\n",ver_);
         }
         else
         {
            dbg3( (char*)"type1Record::load warning invalid ver value %s\n",(char*)&tag_data.front());
         }
      }
      tag = getTagById(3);
      if(tag)
      {
         //1.003 CNT
         tag_data = tag->dataCopy();
         std::vector<unsigned char>::iterator pair_delim_pos;
         while((pair_delim_pos = std::find(tag_data.begin(), tag_data.end(), nistParser::RS()))!=tag_data.end())
         {
            std::vector<unsigned char> pair;
            pair.assign(tag_data.begin(),pair_delim_pos);
            tag_data.erase(tag_data.begin(),pair_delim_pos+1);
            std::vector<unsigned char>::iterator items_delim_pos = std::find(pair.begin(), pair.end(), nistParser::US());
            if(items_delim_pos!=pair.end())
            {
               std::vector<unsigned char> left_part;
               left_part.assign(pair.begin(),items_delim_pos);
               left_part.push_back(0);
               pair.erase(pair.begin(),items_delim_pos+1);
               pair.push_back(0);
               char* end = 0;
               unsigned rec_type = std::strtoul((char*)&left_part.front(),&end,10);
               unsigned idc = std::strtoul((char*)&pair.front(),&end,10);
               if(rec_type!=1)
               {
                  file_content_.push_back(std::pair<unsigned,unsigned>(rec_type,idc));
               }
            }
            else
            {
               dbg0("type1Record::load error invalid 1.003 tag data\n");
               clear();
               return false;
            }
         }
         if(tag_data.size())
         {
            std::vector<unsigned char>::iterator items_delim_pos = std::find(tag_data.begin(), tag_data.end(), nistParser::US());
            if(items_delim_pos!=tag_data.end())
            {
               std::vector<unsigned char> left_part;
               left_part.assign(tag_data.begin(),items_delim_pos);
               left_part.push_back(0);
               tag_data.erase(tag_data.begin(),items_delim_pos+1);
               tag_data.push_back(0);
               char* end = 0;
               unsigned rec_type = std::strtoul((char*)&left_part.front(),&end,10);
               unsigned idc = std::strtoul((char*)&tag_data.front(),&end,10);
               file_content_.push_back(std::pair<unsigned,unsigned>(rec_type,idc));
            }
         }
      }
      tag = getTagById(4);
      if(tag)
      {
         //1.004 TOT
         tag_data = tag->dataCopy();
         transaction_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load transaction %s\n",transaction_.c_str());
      }
      tag = getTagById(5);
      if(tag)
      {
         //1.005 DAT YYYYMMDD
         tag_data = tag->dataCopy();
         transaction_date_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load transaction date %s\n",transaction_date_.c_str());
      }
      tag = getTagById(6);
      if(tag)
      {
         //1.006 PRY 1-9 (optional)
         tag_data = tag->dataCopy();
         priority_ = atoi((char*)&tag_data.front());
         dbg7( (char*)"type1Record::load priority %d\n",priority_);
      }
      tag = getTagById(7);
      if(tag)
      {
         //1.007 DAI CC/agency (up to 32 chars)
         tag_data = tag->dataCopy();
         destination_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load DAI %s\n",destination_.c_str());
      }
      tag = getTagById(8);
      if(tag)
      {
         //1.008 ORI CC/agency (up to 32 chars)
         tag_data = tag->dataCopy();
         originating_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load ORI %s\n",originating_.c_str());
      }
      tag = getTagById(9);
      if(tag)
      {
         //1.009 TCN YYSSSSSSSSA
         tag_data = tag->dataCopy();
         control_number_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load TCN %s\n",control_number_.c_str());
      }
      tag = getTagById(10);
      if(tag)
      {
         //1.010 TCR YYSSSSSSSSA
         tag_data = tag->dataCopy();
         responce_control_number_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load TCR %s\n",responce_control_number_.c_str());
      }
      tag = getTagById(11);
      if(tag)
      {
         //1.011 NSR 19.68
         tag_data = tag->dataCopy();
         scanning_res_ = atof((char*)&tag_data.front());
      }
      tag = getTagById(12);
      if(tag)
      {
         //1.012 NTR 19.68
         tag_data = tag->dataCopy();
         scanning_res_ = atof((char*)&tag_data.front());
      }
      tag = getTagById(13);
      if(tag)
      {
         //1.013 DOM INT-I{US}4.22{GS}
         tag_data = tag->dataCopy();
         domain_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load DOM %s\n",domain_.c_str());
      }
      tag = getTagById(14);
      if(tag)
      {
         //1.014 GMT CCYYMMDDHHMMSSZ
         tag_data = tag->dataCopy();
         g_mean_time_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load GMT %s\n",g_mean_time_.c_str());
      }
      tag = getTagById(15);
      if(tag)
      {
         //1.015 DCS 
         tag_data = tag->dataCopy();
         char_sets_ = (char*)&tag_data.front();
         dbg7( (char*)"type1Record::load DCS %s\n",char_sets_.c_str());
      }

      if(file_content_.size() > 0 && transaction_.length() && control_number_.length()) //Анализ первой записи
      {
         return true;
      }
      else
      {
         dbg0( (char*)"type1Record::load error can't get transaction type or nom\n");
      }

   }
   return false;
}

int type1Record::write(FILE* out, unsigned len)
{
    int stpos = ftell(out);
    unsigned char gs;
    gs = nistParser::GS();
    unsigned char us;
    us = nistParser::US();
    unsigned char rs;
    rs = nistParser::RS();
    unsigned char fs;
    fs = nistParser::FS();
    std::string st;
    if (len)
    {
        st = "1.001:" + itos(len);
    }
    else
    {
        st = "1.001:";
    }
    fwrite(st.c_str(), 1, st.length(), out);
    fwrite(&gs, 1, 1, out);

    std::string ss;
    
    const nistTag* tag = getTagById(2);
    if (tag)
    {
        ss = "1.002:";
        ss += fmtz(4,std::to_string(ver_));
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(3);
    if (tag)
    {
        ss = "1.003:1";
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&us, 1, 1, out);
        ss =  std::to_string(file_content_.size());
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&rs, 1, 1, out);

        for (int i = 0; i < file_content_.size(); i++) 
        {
            ss = std::to_string(file_content_[i].first);
            fwrite(ss.c_str(), 1, ss.length(), out);
            fwrite(&us, 1, 1, out);
            ss = fmtz(2,std::to_string(file_content_[i].second));
            fwrite(ss.c_str(), 1, ss.length(), out);
            if (i + 1 == file_content_.size()) 
            {
                fwrite(&gs, 1, 1, out);
            }
            else 
            {
                fwrite(&rs, 1, 1, out);
            }
        }

    }
    tag = getTagById(4);
    if (tag)
    {
        ss = "1.004:";
        ss += transaction_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(5);
    if (tag)
    {
        ss = "1.005:";
        ss += transaction_date_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(6);
    if (tag)
    {
        ss = "1.006:";
        ss += std::to_string(priority_);
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(7);
    if (tag)
    {
        ss = "1.007:";
        ss += destination_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(8);
    if (tag)
    {
        ss = "1.008:";
        ss += originating_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(9);
    if (tag)
    {
        ss = "1.009:";
        ss += control_number_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(10);
    if (tag)
    {
        ss = "1.010:";
        ss += responce_control_number_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(11);
    if (tag)
    {

        ss = "1.011:";
        ss += std::to_string(scanning_res_);
        ss.resize(11);
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(12);
    if (tag)
    {
        ss = "1.012:";
        ss += std::to_string(transmitting_res_);
        ss.resize(11);
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(13);
    if (tag)
    {
        ss = "1.013:";
        ss += domain_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    tag = getTagById(14);
    if (tag)
    {
        ss = "1.014:";
        ss += g_mean_time_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }          
    tag = getTagById(15);
    if (tag)
    {
        ss = "1.015:";
        ss += char_sets_;
        fwrite(ss.c_str(), 1, ss.length(), out);
        fwrite(&gs, 1, 1, out);
    }
    fseek(out, -1, SEEK_CUR);
    fwrite(&fs, 1, 1, out);
    return ftell(out) - stpos;
}

unsigned type1Record::getRecordType(unsigned rec_no)
{
   /*
   for(unsigned no = 0 ; no<file_content_.size();no++ )
   {
      if( rec_no == file_content_[rec_no].second)
      {
         return file_content_[rec_no].first;
      }
   }
   */
   if(rec_no<file_content_.size())
   {
      return file_content_[rec_no].first;
   }
   return 0;
}

type2Record::type2Record()
   :nistRecord()
{
   idc_ = 0;
   type_ = 2;
}

type2Record::~type2Record()
{
   idc_ = 0;
}

bool type2Record::load(const std::vector<unsigned char>& data, unsigned& offset, bool force)
{
   if(nistRecord::load(data, offset,2,force))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //2.002 IDC 
         tag_data = tag->dataCopy();
         idc_ = (unsigned char)atoi((char*)&tag_data.front());
         dbg7( (char*)"type2Record::load idc %d\n",idc_);
      }
      else
      {
         dbg0( (char*)"type2Record::load error IDC tag missing\n");
         return false;
      }

      tag = getTagById(3);
      if(tag)
      {
         //2.003 SYS
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            sys_ = (char*)&tag_data.front();
            dbg7( (char*)"type2Record::load sys %s\n",sys_.c_str());
         }
      }
      else
      {
         dbg7( (char*)"type2Record::load SYS tag missing\n");
      }
      return true;
   }
   dbg0( (char*)"type2Record::load error\n");
   return false;
}

//void type2Record::write(FILE* out, unsigned len = 0);
//{
//    unsigned char gs;
//    gs = nistParser::GS();
//    unsigned char fs;
//    fs = nistParser::FS();
//    for (int i = 0; i < tags_.size(); i++)
//    {
//        std::string number = fmtz(3, std::to_string(tags_[i].tag_no()));
//        std::string str = std::to_string(type_) + "." + number + ":";
//        fwrite(str.c_str(), 1, str.length(), out);
//        switch (tags_[i].tag_no()) {
//            case 1:
//            break;
//            case 2:
//                fwrite(&fs, 1, 1, out);
//                break;
//        }
//        fwrite(tags_[i].data(), 1, tags_[i].data_size(), out);
//        if (i + 1 == tags_.size())
//        {
//            fwrite(&fs, 1, 1, out);
//        }
//        else
//        {
//            fwrite(&gs, 1, 1, out);
//        }
//    }
//    
//    std::stringstream ss;
//    ss << "2.001:";
//    ss << nistParser::GS();
//    tag = getTagById(2);
//    if (tag)
//    {
//        ss << "002:";
//        ss << idc_;
//        ss << nistParser::GS();
//    }
//    tag = getTagById(3);
//    if (tag)
//    {
//        ss << "003:";
//        ss << sys_;
//        ss << nistParser::GS();
//    }
//
//
//
//    std::string record = ss.str();
//    fwrite(record.c_str(), 1, record.length(), out);
//}


type4Record::type4Record()
   :nistRecord()
{
   type_ = 4;
   idc_ = 0;
   imp_ = 0;
   memset(fgp_,0,sizeof(fgp_));
   isr_ = 0;
   hll_ = 0;
   vll_ = 0;
   cga_ = 0;
}

type4Record::~type4Record()
{
   clear();
}

void type4Record::clear()
{
   type_ = 0;
   idc_ = 0;
   imp_ = 0;
   memset(fgp_,0,sizeof(fgp_));
   isr_ = 0;
   hll_ = 0;
   vll_ = 0;
   cga_ = 0;
   nistRecord::clear();
}

bool type4Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(data.size() && ((offset+sizeof(Type4Header)) <= data.size()))
   {
      unsigned curr_offset = offset;
      const unsigned char* p_data_ = &data.front() + curr_offset;
      Type4Header hdr;
      memset(&hdr,0,sizeof(Type4Header));
      memcpy(&hdr,p_data_,sizeof(Type4Header));
      hdr.len_ = ntohl(hdr.len_);
      hdr.hll_ = ntohs(hdr.hll_);
      hdr.vll_ = ntohs(hdr.vll_);
      curr_offset+=sizeof(Type4Header);
      record_size_ = hdr.len_;
      idc_ = hdr.idc_;
      imp_ = hdr.imp_;
      memcpy(fgp_,hdr.fgp_,sizeof(fgp_));
      isr_ = hdr.isr_;
      hll_ = hdr.hll_;
      vll_ = hdr.vll_;
      cga_ = hdr.cga_;
      if(hdr.len_>sizeof(Type4Header))
      {
         image_data_ = p_data_+sizeof(Type4Header);
         image_data_size_ = hdr.len_ - sizeof(Type4Header);
      }
      else
      {
         dbg7("type4Record::load empty image record %d\n",hdr.idc_);
      }
      offset += record_size_;
      //std::cout << "record size = " << record_size_;
      return true;
   }
   else
   {
      dbg0("type4Record::load error invalid data\n");
   }
   clear();
   return false;
}

int type4Record::write(FILE* out, unsigned len)
{
    int stpos = ftell(out);
    unsigned char fs;
    fs = nistParser::FS();
    Type4Header hdr;
    unsigned recordsize = record_size_;
    if (len)
    {
        recordsize = len;
    } 

    hdr.len_ = htonl(recordsize);
    
    //std::cout << "record size = " << record_size_;
    hdr.idc_ = idc_;
    hdr.imp_ = imp_;
    memcpy(hdr.fgp_, fgp_, sizeof(fgp_));
    hdr.isr_ = isr_;
    hdr.hll_ = htons(hll_);

    hdr.vll_ = htons(vll_);
    hdr.cga_ = cga_;
    fwrite(&hdr, sizeof(Type4Header), 1, out);
    if (image_data_)
    {
        fwrite(image_data_, 1, image_data_size_, out);
    }
    return ftell(out) - stpos;
}

type7Record::type7Record()
   : type4Record()
{
   type_ = 7;
   imt_ = 0; 
   imd_ = 0;
   memset(pcn_,0,sizeof(pcn_));
   memset(imr_,0,sizeof(imr_));
}

type7Record::~type7Record()
{
}

bool type7Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   //return type4Record::load(data,offset);
   if(data.size() && ((offset+sizeof(Type7Header)) <= data.size()))
   {
      unsigned curr_offset = offset;
      const unsigned char* p_data_ = &data.front() + curr_offset;
      Type7Header hdr;
      memset(&hdr,0,sizeof(Type7Header));
      memcpy(&hdr,p_data_,sizeof(Type7Header));
      hdr.len_ = ntohl(hdr.len_);
      hdr.hll_ = ntohs(hdr.hll_);
      hdr.vll_ = ntohs(hdr.vll_);
      curr_offset+=sizeof(Type7Header);

      record_size_ = hdr.len_;
      idc_ = hdr.idc_;
      imt_ = hdr.imt_;
      memcpy(pcn_,hdr.pcn_,sizeof(pcn_));
      memcpy(imr_,hdr.imr_,sizeof(pcn_));
      hll_ = hdr.hll_;
      vll_ = hdr.vll_;
      cga_ = hdr.cga_;
      if(hdr.len_>sizeof(Type7Header))
      {
         image_data_ = p_data_+sizeof(Type7Header);
         image_data_size_ = hdr.len_ - sizeof(Type7Header);
      }
      else
      {
         dbg7("type7Record::load empty image record %d\n",hdr.idc_);
      }
      offset += record_size_;
      return true;
   }
   else
   {
      dbg0("type7Record::load error invalid data\n");
   }
   clear();
   return false;
}

int type7Record::write(FILE* out, unsigned len)
{
    int stpos = ftell(out);
    Type7Header hdr;

    unsigned recordsize = record_size_;
    if (len)
    {
        recordsize = len;
    }

    hdr.len_ = htonl(recordsize);
    hdr.hll_ = htons(hll_);
    hdr.vll_ = htons(vll_);

    hdr.idc_ = idc_;
    hdr.imt_ = imt_;
    memcpy(hdr.pcn_, pcn_, sizeof(pcn_));
    memcpy(hdr.imr_, imr_, sizeof(pcn_));
    hdr.cga_ = cga_;
    fwrite(&hdr, sizeof(Type7Header), 1, out);
    if (image_data_)
    {
        fwrite(image_data_, 1, image_data_size_, out);
    }
    return ftell(out) - stpos;
}

type8Record::type8Record()
   : type4Record()
{
   type_ = 8;
   sig_ = 0; 
   srt_ = 0;
}

type8Record::~type8Record()
{
}

bool type8Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(data.size() && ((offset+sizeof(Type8Header)) <= data.size()))
   {
      unsigned curr_offset = offset;
      const unsigned char* p_data_ = &data.front() + curr_offset;
      Type8Header hdr;
      memset(&hdr,0,sizeof(Type8Header));
      memcpy(&hdr,p_data_,sizeof(Type8Header));
      hdr.len_ = ntohl(hdr.len_);
      hdr.hll_ = ntohs(hdr.hll_);
      hdr.vll_ = ntohs(hdr.vll_);
      curr_offset+=sizeof(Type8Header);

      record_size_ = hdr.len_;
      idc_ = hdr.idc_;
      sig_ = hdr.sig_;
      hll_ = hdr.hll_;
      vll_ = hdr.vll_;
      srt_ = hdr.srt_;
      cga_ = 0; //Сжатие указывается типом подписи  srt_
      if(hdr.len_>sizeof(Type7Header))
      {
         image_data_ = p_data_+sizeof(Type8Header);
         image_data_size_ = hdr.len_ - sizeof(Type8Header);
      }
      else
      {
         dbg7("type8Record::load empty image record %d\n",hdr.idc_);
      }
      offset += record_size_;
      return true;
   }
   else
   {
      dbg0("type8Record::load error invalid data\n");
   }
   clear();
   return false;
}

int type8Record::write(FILE* out, unsigned len)
{
    int stpos = ftell(out);
    unsigned char fs;
    fs = nistParser::FS();
    Type8Header hdr;
    unsigned recordsize = record_size_;
    if (len)
    {
        recordsize = len;
    }
    hdr.len_ = htonl(recordsize);
    hdr.hll_ = htons(hll_);
    hdr.vll_ = htons(vll_);

    hdr.idc_ = idc_;
    hdr.sig_ = sig_;
    hdr.srt_ = srt_;
    fwrite(&hdr, sizeof(Type8Header), 1, out);
    if (image_data_)
    {
        fwrite(image_data_, 1, image_data_size_, out);
    }
    return ftell(out) - stpos;
}


type9Record::type9Record() 
   : nistRecord()
{   
   type_ = 9;
}

type9Record::~type9Record()
{
}

bool type9Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   nistTag new_tag;
   unsigned start_offset = offset;
   if(new_tag.load(data,offset,0))
   {
      if(new_tag.rec()==9 && new_tag.tag_no()==1)
      {
         std::vector<unsigned char> tag_data;
         tag_data = new_tag.dataCopy();
         unsigned rec_size = atoi((char*)&tag_data.front());
         if(rec_size)
         {            
            type_ = 9;
            offset_ = start_offset;
            record_size_ = rec_size;
            offset = offset_+record_size_;
            return true;
         }
      }
   }
   clear();
   return false;
}
type10Record::type10Record()
   :type4Record()
{
   type_ = 10;
   slc_ = 0;
   hps_ = 0;
   vps_ = 0;
   cga_ = "";
   imt_ = "";
   ori_ = "";
   photo_date_ = "";
   hll_ = 0;
   vll_ = 0;
   csp_ = "";
   pos_ = "";
   poa_ = "";
   pxs_ = "";
}

type10Record::~type10Record()
{
   idc_ = 0;
}

bool type10Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(nistRecord::load(data, offset,type_))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //10.002 IDC 
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            idc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load idc %d\n",idc_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load error IDC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error IDC tag missing\n");
      }

      tag = getTagById(3);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            imt_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load imp %s\n",imp_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load error IMP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error IMP tag missing\n");
      }

      tag = getTagById(4);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            ori_ = (const char*) &tag_data.front();
            dbg7( (char*)"Type10Record::load ORI %s\n",ori_.c_str());
         }
         else
         {
            dbg0( (char*)"Type10Record::load ORI tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error ORI tag missing\n");
      }

      tag = getTagById(5);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            photo_date_ = (const char*) &tag_data.front();
            dbg7( (char*)"Type10Record::load PHD %s\n",photo_date_.c_str());
         }
         else
         {
            dbg0( (char*)"Type10Record::load PHD tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error PHD tag missing\n");
      }

      tag = getTagById(6);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load HLL %d\n",hll_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load error HLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error HLL tag missing\n");
      }

      tag = getTagById(7);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load VLL %d\n",vll_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load error VLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error VLL tag missing\n");
      }

      tag = getTagById(8);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            slc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load SLC %d\n",slc_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load SLC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error SLC tag missing\n");
      }

      tag = getTagById(9);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load HPS %d\n",hps_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load HPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error HPS tag missing\n");
      }

      tag = getTagById(10);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"Type10Record::load VPS %d\n",vps_);
         }
         else
         {
            dbg0( (char*)"Type10Record::load VPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error VPS tag missing\n");
      }

      tag = getTagById(11);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            cga_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load CGA %s\n",cga_.c_str());
         }
         else
         {
            dbg0( (char*)"Type10Record::load CGA tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error CGA tag missing\n");
      }

      tag = getTagById(12);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            csp_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load CSP %s\n",csp_.c_str());
         }
         else
         {
            dbg0( (char*)"Type10Record::load CSP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"Type10Record::load error CSP tag missing\n");
      }

      tag = getTagById(20);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            pos_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load POS %s\n",pos_.c_str());
         }
      }

      tag = getTagById(21);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            poa_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load POA %s\n",poa_.c_str());
         }
      }
      tag = getTagById(22);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            pxs_ = (const char*)&tag_data.front();
            dbg7( (char*)"Type10Record::load PXS %s\n",pxs_.c_str());
         }
      }

      tag = getTagById(999);
      if(tag)
      {
         //Field 10.999: Image data (DAT)
         image_data_ = tag->data();
         image_data_size_ = tag->data_size();
         dbg7( (char*)"Type10Record::load image data size %d\n",image_data_size_);
      }
      else
      {
         image_data_ = 0;
         image_data_size_ = 0;
         dbg0( (char*)"Type10Record::load error image data tag missing\n");
      }
      return true;
   }
   clear();
   dbg0( (char*)"Type10Record::load error\n");
   return false;
}


type13Record::type13Record()
   :type4Record()
{
   type_ = 13;
   slc_ = 0;
   hps_ = 0;
   vps_ = 0;
   cga_ = "";
   bpx_ = 0;
}

type13Record::~type13Record()
{
   idc_ = 0;
}

bool type13Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(nistRecord::load(data, offset,type_))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //13.002 IDC 
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            idc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load idc %d\n",idc_);
         }
         else
         {
            dbg0( (char*)"type13Record::load error IDC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error IDC tag missing\n");
      }

      tag = getTagById(3);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            imp_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load imp %d\n",imp_);
         }
         else
         {
            dbg0( (char*)"type13Record::load error IMP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error IMP tag missing\n");
      }

      tag = getTagById(4);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            ori_ = (const char*) &tag_data.front();
            dbg7( (char*)"type13Record::load ORI %s\n",ori_.c_str());
         }
         else
         {
            dbg0( (char*)"type13Record::load ORI tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error ORI tag missing\n");
      }

      tag = getTagById(5);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            lcd_ = (const char*) &tag_data.front();
            dbg7( (char*)"type13Record::load PCD %s\n",lcd_.c_str());
         }
         else
         {
            dbg0( (char*)"type13Record::load PCD tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error PCD tag missing\n");
      }

      tag = getTagById(6);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load HLL %d\n",hll_);
         }
         else
         {
            dbg0( (char*)"type13Record::load error HLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error HLL tag missing\n");
      }

      tag = getTagById(7);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load VLL %d\n",vll_);
         }
         else
         {
            dbg0( (char*)"type13Record::load error VLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error VLL tag missing\n");
      }

      tag = getTagById(8);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            slc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load SLC %d\n",slc_);
         }
         else
         {
            dbg0( (char*)"type13Record::load SLC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error SLC tag missing\n");
      }

      tag = getTagById(9);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load HPS %d\n",hps_);
         }
         else
         {
            dbg0( (char*)"type13Record::load HPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error HPS tag missing\n");
      }

      tag = getTagById(10);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load VPS %d\n",vps_);
         }
         else
         {
            dbg0( (char*)"type13Record::load VPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error VPS tag missing\n");
      }

      tag = getTagById(11);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            cga_ = (const char*)&tag_data.front();
            dbg7( (char*)"type13Record::load CGA %s\n",cga_.c_str());
         }
         else
         {
            dbg0( (char*)"type13Record::load CGA tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error CGA tag missing\n");
      }

      tag = getTagById(12);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            bpx_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type13Record::load PBX %d\n",bpx_);
         }
         else
         {
            dbg0( (char*)"type13Record::load PBX tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error PBX tag missing\n");
      }

      tag = getTagById(13);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            fgp_ = (char*)&tag_data.front();
            dbg7( (char*)"type13Record::load FGP %d\n",fgp_.c_str());
         }
         else
         {
            dbg0( (char*)"type13Record::load FGP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type13Record::load error PLP tag missing\n");
      }

      tag = getTagById(20);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            com_ = (char*)&tag_data.front();
            dbg7( (char*)"type13Record::load COM %s\n",com_.c_str());
         }
      }


      tag = getTagById(999);
      if(tag)
      {
         //Field 15.999: Image data (DAT)
         image_data_ = tag->data();
         image_data_size_ = tag->data_size();
         dbg7( (char*)"type13Record::load image data size %d\n",image_data_size_);
      }
      else
      {
         image_data_ = 0;
         image_data_size_ = 0;
         dbg0( (char*)"type13Record::load error image data tag missing\n");
      }
      return true;
   }
   clear();
   dbg0( (char*)"type13Record::load error\n");
   return false;
}

unsigned char type13Record::getFGP()
{
   return atoi(fgp_.c_str());
}

type14Record::type14Record()
   :type4Record()
{
   type_ = 14;
   slc_ = 0;
   hps_ = 0;
   vps_ = 0;
   cga_ = "";
   pbx_ = 0;
}

type14Record::~type14Record()
{
   idc_ = 0;
}

bool type14Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(nistRecord::load(data, offset,type_))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //14.002 IDC 
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            idc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load idc %d\n",idc_);
         }
         else
         {
            dbg0( (char*)"type14Record::load error IDC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error IDC tag missing\n");
      }

      tag = getTagById(3);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            imp_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load imp %d\n",imp_);
         }
         else
         {
            dbg0( (char*)"type14Record::load error IMP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error IMP tag missing\n");
      }

      tag = getTagById(4);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            ori_ = (const char*) &tag_data.front();
            dbg7( (char*)"type14Record::load ORI %s\n",ori_.c_str());
         }
         else
         {
            dbg0( (char*)"type14Record::load ORI tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error ORI tag missing\n");
      }

      tag = getTagById(5);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            tcd_ = (const char*) &tag_data.front();
            dbg7( (char*)"type14Record::load TCD %s\n",tcd_.c_str());
         }
         else
         {
            dbg0( (char*)"type14Record::load TCD tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error TCD tag missing\n");
      }

      tag = getTagById(6);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load HLL %d\n",hll_);
         }
         else
         {
            dbg0( (char*)"type14Record::load error HLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error HLL tag missing\n");
      }

      tag = getTagById(7);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load VLL %d\n",vll_);
         }
         else
         {
            dbg0( (char*)"type14Record::load error VLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error VLL tag missing\n");
      }

      tag = getTagById(8);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            slc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load SLC %d\n",slc_);
         }
         else
         {
            dbg0( (char*)"type14Record::load SLC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error SLC tag missing\n");
      }

      tag = getTagById(9);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load HPS %d\n",hps_);
         }
         else
         {
            dbg0( (char*)"type14Record::load HPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error HPS tag missing\n");
      }

      tag = getTagById(10);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load VPS %d\n",vps_);
         }
         else
         {
            dbg0( (char*)"type14Record::load VPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error VPS tag missing\n");
      }

      tag = getTagById(11);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            cga_ = (const char*)&tag_data.front();
            dbg7( (char*)"type14Record::load CGA %s\n",cga_.c_str());
         }
         else
         {
            dbg0( (char*)"type14Record::load CGA tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error CGA tag missing\n");
      }

      tag = getTagById(12);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            pbx_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load PBX %d\n",pbx_);
         }
         else
         {
            dbg0( (char*)"type14Record::load PBX tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error PBX tag missing\n");
      }

      tag = getTagById(13);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            fgp_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type14Record::load PLP %d\n",fgp_);
         }
         else
         {
            dbg0( (char*)"type14Record::load PLP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type14Record::load error PLP tag missing\n");
      }

      tag = getTagById(20);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            com_ = (char*)&tag_data.front();
            dbg7( (char*)"type14Record::load COM %s\n",com_.c_str());
         }
      }

      tag = getTagById(999);
      if(tag)
      {
         //Field 14.999: Image data (DAT)
         image_data_ = tag->data();
         image_data_size_ = tag->data_size();
         dbg7( (char*)"type14Record::load image data size %d\n",image_data_size_);
      }
      else
      {
         image_data_ = 0;
         image_data_size_ = 0;
         dbg0( (char*)"type14Record::load error image data tag missing\n");
      }
      return true;
   }
   clear();
   dbg0( (char*)"type14Record::load error\n");
   return false;
}

type15Record::type15Record()
   :type4Record()
{
   type_ = 15;
   slc_ = 0;
   hps_ = 0;
   vps_ = 0;
   cga_ = "";
   pbx_ = 0;
   plp_ = 0;
}

type15Record::~type15Record()
{
   idc_ = 0;
}

bool type15Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   if(nistRecord::load(data, offset,type_))
   {
      std::vector<unsigned char> tag_data;
      const nistTag* tag = getTagById(2);
      if(tag)
      {
         //15.002 IDC 
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            idc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load idc %d\n",idc_);
         }
         else
         {
            dbg0( (char*)"type15Record::load error IDC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error IDC tag missing\n");
      }

      tag = getTagById(3);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            imp_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load imp %d\n",imp_);
         }
         else
         {
            dbg0( (char*)"type15Record::load error IMP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error IMP tag missing\n");
      }

      tag = getTagById(4);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            ori_ = (const char*) &tag_data.front();
            dbg7( (char*)"type15Record::load ORI %s\n",ori_.c_str());
         }
         else
         {
            dbg0( (char*)"type15Record::load ORI tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error ORI tag missing\n");
      }

      tag = getTagById(5);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            pcd_ = (const char*) &tag_data.front();
            dbg7( (char*)"type15Record::load PCD %s\n",pcd_.c_str());
         }
         else
         {
            dbg0( (char*)"type15Record::load PCD tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error PCD tag missing\n");
      }

      tag = getTagById(6);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load HLL %d\n",hll_);
         }
         else
         {
            dbg0( (char*)"type15Record::load error HLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error HLL tag missing\n");
      }

      tag = getTagById(7);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vll_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load VLL %d\n",vll_);
         }
         else
         {
            dbg0( (char*)"type15Record::load error VLL tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error VLL tag missing\n");
      }

      tag = getTagById(8);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            slc_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load SLC %d\n",slc_);
         }
         else
         {
            dbg0( (char*)"type15Record::load SLC tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error SLC tag missing\n");
      }

      tag = getTagById(9);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            hps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load HPS %d\n",hps_);
         }
         else
         {
            dbg0( (char*)"type15Record::load HPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error HPS tag missing\n");
      }

      tag = getTagById(10);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            vps_ = atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load VPS %d\n",vps_);
         }
         else
         {
            dbg0( (char*)"type15Record::load VPS tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error VPS tag missing\n");
      }

      tag = getTagById(11);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            cga_ = (const char*)&tag_data.front();
            dbg7( (char*)"type15Record::load CGA %s\n",cga_.c_str());
         }
         else
         {
            dbg0( (char*)"type15Record::load CGA tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error CGA tag missing\n");
      }

      tag = getTagById(12);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            pbx_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load PBX %d\n",pbx_);
         }
         else
         {
            dbg0( (char*)"type15Record::load PBX tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error PBX tag missing\n");
      }

      tag = getTagById(13);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            plp_ = (unsigned char)atoi((char*)&tag_data.front());
            dbg7( (char*)"type15Record::load PLP %d\n",plp_);
         }
         else
         {
            dbg0( (char*)"type15Record::load PLP tag empty\n");
         }
      }
      else
      {
         dbg0( (char*)"type15Record::load error PLP tag missing\n");
      }

      tag = getTagById(20);
      if(tag)
      {
         tag_data = tag->dataCopy();
         if(tag_data.size())
         {
            com_ = (char*)&tag_data.front();
            dbg7( (char*)"type15Record::load COM %s\n",com_.c_str());
         }
      }


      tag = getTagById(999);
      if(tag)
      {
         //Field 15.999: Image data (DAT)
         image_data_ = tag->data();
         image_data_size_ = tag->data_size();
         dbg7( (char*)"type15Record::load image data size %d\n",image_data_size_);
      }
      else
      {
         image_data_ = 0;
         image_data_size_ = 0;
         dbg0( (char*)"type15Record::load error image data tag missing\n");
      }
      return true;
   }
   clear();
   dbg0( (char*)"type15Record::load error\n");
   return false;
}

int type15Record::write(FILE* out, unsigned len)
{
    int stpos = ftell(out);
    unsigned char gs;
    gs = nistParser::GS();
    unsigned char fs;
    fs = nistParser::FS();
    std::cout << std::endl;
    for (int i = 0; i < tags_.size(); i++)
    {
        
        std::string number = fmtz(3, std::to_string(tags_[i].tag_no()));
        std::string str = std::to_string(type_) + "." + number + ":";
        fwrite(str.c_str(), 1, str.length(), out);
        int kek = ftell(out);
        int diff = tags_[i].offset_ - kek;

        std::cout << i << " " << tags_[i].tag_no() << "  " << diff << "\n";
        switch (tags_[i].tag_no()) 
        {
            case 1:
            {
                if (len) 
                {
                    std::string x = itos(len);
                    fwrite(x.c_str(), 1, x.length(), out);
                }
                break;
            }
            case 2: 
            {
                std::string x = std::to_string(idc_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }
            case 3:
            {
                std::string x = std::to_string(imp_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }
            case 4:
            {
                fwrite(ori_.c_str(), 1, ori_.length(), out);
                break;
            }
            case 5:
            {
                fwrite(pcd_.c_str(), 1, pcd_.length(), out);
                break;
            }
            case 6:
            {
                std::string x = std::to_string(hll_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }

            case 7:
            {
                std::string x = std::to_string(vll_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }

            case 8:
            {
                fwrite(&slc_, 1, 1, out);
                break;
            }

            case 9:
            {
                std::string x = std::to_string(hps_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }

            case 10:
            {
                std::string x = std::to_string(vps_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }

            case 11:
            {
                fwrite(cga_.c_str(), 1, cga_.length(), out);
                break;
            }
            case 12:
            {
                fwrite(&pbx_, 1, 1, out);
                break;
            }

            case 13:
            {
                std::string x = std::to_string(plp_);
                fwrite(x.c_str(), 1, x.length(), out);
                break;
            }
 
            case 20:
            {
                fwrite(com_.c_str(), 1, com_.length(), out);
                break;
            }
            case 999:
                if (image_data_)
                {
                    fwrite(image_data_, 1, image_data_size_, out);
                }
                break;
            default:
                fwrite(tags_[i].data(), 1, tags_[i].data_size(), out);
            break;
        }
             
        
        if (i + 1 == tags_.size())
        {
            fwrite(&fs, 1, 1, out);
        }
        else
        {
            fwrite(&gs, 1, 1, out);
        }

    }
    return ftell(out) - stpos;
}

type99Record::type99Record() 
   : nistRecord()
{   
   type_ = 99;
}

type99Record::~type99Record()
{
}

bool type99Record::load(const std::vector<unsigned char>& data, unsigned& offset)
{
   nistTag new_tag;
   unsigned start_offset = offset;
   if(new_tag.load(data,offset,0))
   {
      if(new_tag.rec()==99 && new_tag.tag_no()==1)
      {
         std::vector<unsigned char> tag_data;
         tag_data = new_tag.dataCopy();
         unsigned rec_size = atoi((char*)&tag_data.front());
         if(rec_size)
         {            
            type_ = 99;
            offset_ = start_offset;
            record_size_ = rec_size;
            offset = offset_+record_size_;
            return true;
         }
      }
   }
   clear();
   return false;
}

nistParser::nistParser()
{
   dbg7( (char*)"nistParser::nistParser\n");
}

nistParser::~nistParser()
{
   dbg7( (char*)"nistParser::~nistParser\n");
   for(unsigned record_no=0;record_no<records_.size();record_no++)
   {
      delete records_[record_no];
   }
   records_.clear();
}

bool nistParser::load(const std::string& file,bool force)
{
   dbg7( (char*)"nistParser::load %s\n",file.c_str());
   bool res = false;
   if(readFile(file,file_data_))
   {
      dbg7( (char*)"nistParser::load file read Ok\n");
      return load(file_data_,force);
   }
   else
   {
      dbg0("nistParser::load file read error\n");
   }

   return res;
}

bool nistParser::load(const std::vector<unsigned char>& file_data, bool force)
{
   dbg7( (char*)"nistParser::load from memory data size %d\n",file_data.size());
   bool res = false;
   unsigned offset = 0;
   err_msg_ = "";

   header_.clear();
   records_.clear();

   if(header_.load(file_data,offset,force))
   {
      res = true;
   }

   if(!res)
   {
      dbg0("nistParser::load from memory parse error\n");
      return false;
   }
   else
   {
      unsigned recs = header_.getRecordsCnt();
      for(unsigned rec_no=0; rec_no<recs;rec_no++)
      {
         

         unsigned rec_type  = header_.getRecordType(rec_no);
     
         dbg7("nistParser::load from record type %d\n",rec_type);
         switch(rec_type)
         {
            case 1:
               break;
            case 2:
               {
                  type2Record* new_rec = new type2Record();
                  if(!new_rec->load(file_data,offset,force))
                  {
                     delete new_rec;
                     err_msg_ += "Invalid Type2 record ";
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 4:
               {
                  type4Record* new_rec = new type4Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type4 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 7:
               {
                  type7Record* new_rec = new type7Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type7 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
                  break;
               }
            case 8:
               {
                  type8Record* new_rec = new type8Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type8 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
                  break;
               }
            case 9:
               {
                  type9Record* new_rec = new type9Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type9 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
                  break;
               }
            case 10:
               {
                  type10Record* new_rec = new type10Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type10 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 13:
               {
                  type13Record* new_rec = new type13Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type13 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 14:
               {
                  type14Record* new_rec = new type14Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type14 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 15:
               {
                  type15Record* new_rec = new type15Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type15 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
               }
               break;
            case 99:
               {
                  type99Record* new_rec = new type99Record();
                  if(!new_rec->load(file_data,offset))
                  {
                     err_msg_ += "Invalid Type99 record ";
                     delete new_rec;
                     res = false;
                  }
                  else
                  {
                     records_.push_back(new_rec);
                  }
                  break;
               }
            default:
               dbg0("nistParser::load from memory error: unknown record type %d\n",rec_type);
               res = false;
               break;
         };
         if(!res && !force)
         {
            break;
         }
         records_.back()->offset_ = offset;
         std::cout << "\n" << "offset at load = " << offset << " type = " << rec_type;
      }
   }
   return force? true:res;
}

//bool nistParser::write(std::vector<nistRecord*> records_) {
//
//    std::ofstream outfile("test.txt");
//
//    outfile << "my text here!" << std::endl;
//
//    outfile.close();
//}


std::string nistParser::getDOM()
{
   return header_.getDOM();
}

std::string nistParser::getTOT()
{
   return header_.getTOT();
}

std::string nistParser::getTCN()
{
   return header_.getTCN();
}

std::string nistParser::getTCR()
{
   return header_.getTCR();
}

std::string nistParser::getORI()
{
   return header_.getORI();
}

std::string nistParser::getDAI()
{
   return header_.getDAI();
}

double nistParser::getISR()
{
   return header_.getISR();
}

std::vector<nistRecord*> nistParser::getRecords(unsigned type)
{
   std::vector<nistRecord*> res;
   for(unsigned rec_no=0;rec_no<records_.size();rec_no++)
   {
      if(records_[rec_no]->type()==type)
      {
         res.push_back(records_[rec_no]);
      }
   }
   return res;
}

bool nistParser::readFile(const std::string& file_name,std::vector<unsigned char>& content)
{
   FILE *in = fopen(file_name.c_str(), "rb");
   if(in>0)
   {
      unsigned long length;
      fseek(in, 0L, SEEK_END);
      length = ftell(in);
      if(length>0)
      {
         fseek(in, 0L,SEEK_SET);
         content.resize(length);
         unsigned long readed = fread(&content[0], 1, length, in);
         fclose(in);
         dbg7( (char*)"nistParser::readFile file %s readed, file size %d readed %d\n", file_name.c_str(),length,readed);
         return (readed == length);
      }
      else
      {
         fclose(in);
         dbg0("nistParser::readFile file %s zero size\n", file_name.c_str());
      }
   }
   else
   {
      dbg0("nistParser::readFile file %s open error\n", file_name.c_str());
   }
   return false;
}

bool nistParser::writeFile(const std::string& output_file_name) 
{
    FILE *out = fopen(output_file_name.c_str(), "wb");

    int len = header_.write(out, 0);
    fseek(out, -len, SEEK_CUR);
    header_.write(out, len);
        for (int rec_no = 0; rec_no < records_.size(); rec_no++) 
        {
            len = (records_[rec_no])->write(out, 0);
            fseek(out, -len, SEEK_CUR);
            (records_[rec_no])->write(out, len);
            int pos = ftell(out);
            std::cout << "\n" << "offset at write " << ftell(out) << " delta " << records_[rec_no]->offset_-pos << " type " << std::to_string(records_[rec_no]->type());

        }
 
    return true;
}
