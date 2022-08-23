#ifndef NIST_PARSER_H
#define NIST_PARSER_H

#include <string>
#include <vector>
#include <utility>




///! Базовый класс тега ANSI-NIST файла
class nistTag
{ 
public:
   nistTag();
   virtual ~nistTag();
   virtual bool load(const std::vector<unsigned char>&, unsigned& offset,unsigned offset_to_record_end = 0);
   //!Номер записи тега
   unsigned rec()const{return rec_;}
   //!Номер тега
   unsigned tag_no()const{return nom_;}
   //!Размер данных (не включает идентификатор тега и замыкающий разделитель)
   unsigned data_size()const{return size_;}
   //!Возвращает указатель на начало данных тега в исходном буфере
   const unsigned char* data()const{return data_;} 
   //!Возвращает копию данных тега, добавляет замыкающий ноль
   std::vector<unsigned char> dataCopy() const;
   unsigned offset_;
protected:
   ///Смещение начала данных тега относительно начала файла
   //unsigned offset_; ------------------------------------------------------- fixme
   ///Размер данных
   unsigned size_;
   ///Тип записи
   unsigned rec_;
   ///Номер тега
   unsigned nom_;
   //!Указатель на начало данных тега в исходном буфере. 
   //!Началом считается позиция после доветочия, отделяющего идентификатор тега от данных 
   const unsigned char* data_;
};

///! Базовый класс записи ANSI-NIST файла
class nistRecord
{ 
public:
   nistRecord();
   virtual ~nistRecord();
   virtual bool load(const std::vector<unsigned char>&, unsigned& offset,unsigned type,bool force=false);
   virtual int write(FILE* out, unsigned len = 0);

   unsigned recordSize();
   unsigned type(){return type_;}
   unsigned tagsCnt(){return tags_.size();}
   const nistTag* getTag(unsigned no);
   const nistTag* getTagById(unsigned id);
   const unsigned char* getImgData(){return image_data_;}
   const unsigned getImgDataSize(){return image_data_size_;}
public:
   //virtual bool writeTag(nistTag& tag, FILE* out);
   virtual void clear();
   //!Смещение начала данных записи относительно начала файла
   unsigned offset_;
   //!Тип записи
   unsigned type_;
   //!Размер записи
   unsigned record_size_;
   //!Список тегов
   std::vector<nistTag> tags_;
   //!Указатель на данные изображения
   const unsigned char* image_data_;
   //!Размер данных изображения
   unsigned image_data_size_;
};

///! Запись Type-1 - заголовок файла
class type1Record : public nistRecord
{   
public:
   type1Record();
   ~type1Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset,bool force=false);
   int write(FILE* out, unsigned len = 0);
   std::string getDOM(){return domain_;}
   std::string getTOT(){return transaction_;}
   std::string getTCN(){return control_number_;}
   std::string getTCR(){return responce_control_number_;}
   std::string getORI(){return originating_;}
   std::string getDAI(){return destination_;}
   std::string getDCS(){return char_sets_;}
   double getISR(){return scanning_res_;}
   unsigned getRecordsCnt(){return file_content_.size();}
   unsigned getRecordType(unsigned rec_no);
protected:
   
   unsigned ver_;                                              ///1.002 VER 
   std::vector<std::pair<unsigned,unsigned> > file_content_;   ///1.003 CNT
   std::string transaction_;                                   ///1.004 TOT
   std::string transaction_date_;                              ///1.005 DAT YYYYMMDD
   unsigned priority_;                                         ///1.006 PRY 1-9 (optional)
   std::string destination_;                                   ///1.007 DAI CC/agency (up to 32 chars)
   std::string originating_;                                   ///1.008 ORI CC/agency (up to 32 chars)
   std::string control_number_;                                ///1.009 TCN YYSSSSSSSSA
   std::string responce_control_number_;                       ///1.010 TCR YYSSSSSSSSA
   double scanning_res_;                                       ///1.011 NSR 19.68
   double transmitting_res_;                                   ///1.012 NTR 19.68
   std::string domain_;                                        ///1.013 DOM INT-I{US}4.22{GS}
   std::string g_mean_time_;                                   ///1.014 GMT CCYYMMDDHHMMSSZ
   std::string char_sets_;                                     ///1.015 DCS 
};

///! Запись Type-2 - текстовые данные
class type2Record : public nistRecord
{   
public:
   type2Record();
   ~type2Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset,bool force=false);
   //int write(FILE* out, unsigned len = 0);
protected:
   // bool writeTag(nistTag& tag, FILE* out);
   /*
      Field 2.002: Image Designation Character (IDC)  
      The IDC contained in this mandatory field is an ASCII representation of the IDC as defined in 
      the file content field of the Type-1 record.
   */
   unsigned char idc_;                            
   /*
      2.1.3  Field 2.003: System Information (SYS)  
      This field is mandatory and contains four bytes which indicate which version of the INT-I this 
      particular Type-2 record complies with. This feature gives the INT-I the ability to evolve as 
      necessary while still allowing a system to process transactions generated by a system complying 
      with an older version of the INT-I. 

      The first two bytes specify the major version number, the second two the minor revision number. 
      For example, this implementation is version 4 revision 22 and would be represented as "0422".  
   */
   std::string sys_;
};


/*! Запись Type-4 - бинарная запись, дакдилоскопические изображения 
   Каждый тип бинарной записи имеет свою структуру, 
   по этому каждый класс записи с бинарными записями имеет свой метод загрузки
*/
class type4Record : public nistRecord
{   
public:
   type4Record();
   virtual ~type4Record();
   virtual bool load(const std::vector<unsigned char>&, unsigned& offset);
   virtual int write(FILE* out, unsigned len = 0);
   unsigned getHLL(){return hll_;}
   unsigned getVLL(){return vll_;}
   unsigned char getCGA(){return cga_;}
   virtual unsigned getISR(){return isr_;}
   unsigned char getIMP(){return imp_;}
   virtual unsigned char getFGP(){return fgp_[0];}
   unsigned char getIDC(){return idc_;}
protected:
   virtual void clear();
   /*!Field 4.002: Image Designation Character (IDC) 
   This is the one-byte binary representation of the IDC number given in the header file.
   */
   unsigned char idc_;

   /*!Field 4.003: Impression Type (IMP)   
      The impression type is a single-byte field occupying the sixth byte of the record.                                                                 
   0  Live-scan of plain fingerprint 
   1  Live-scan of rolled fingerprint 
   2  Non-live scan impression of plain fingerprint captured from paper 
   3  Non-live scan impression of rolled fingerprint captured from paper 
   4  Latent impression captured directly 
   5 Latent tracing 
   6 Latent photo 
   7 Latent lift 
   8 Swipe 
   9 Unknown 
   */
   unsigned char imp_;

   /*!
   4.1.4  Field 4.004: Finger Position (FGP) 
 
   This fixed-length field of 6 bytes occupies the seventh through twelfth byte positions of a Type-4 
   record. It contains possible finger positions beginning in the left most byte (byte 7 of the record). 
   The known or most probable finger position is taken from the following table. Up to five 
   additional fingers may be referenced by entering  the alternate finger positions in the remaining 
   five bytes using the same format. If fewer than five finger position references are to be used the 
   unused bytes are filled with binary 255. To reference all finger positions code 0, for unknown, is 
   used.  
 
   Table 4.2   - Finger position code and maximum size 
 
   Finger position            Finger code  Width (mm)  Length (mm) 
   Unknown                          0        40.0        40.0 
   Right thumb                      1        45.0        40.0 
   Right index finger               2        40.0        40.0 
   Right middle finger              3        40.0        40.0 
   Right ring finger                4        40.0        40.0 
   Right little finger              5        33.0        40.0 
   Left thumb                       6        45.0        40.0 
   Left index finger                7        40.0        40.0 
   Left middle finger               8        40.0        40.0 
   Left ring finger                 9        40.0        40.0 
   Left little finger               10       33.0        40.0 
   Plain right thumb                11       30.0        55.0 
   Plain left thumb                 12       30.0        55.0 
   Plain right four fingers         13       70.0        65.0 
   Plain left four fingers          14       70.0        65.0 
   */
   unsigned char fgp_[6];

   /*!
      4.1.5  Field 4.005: Image Scanning Resolution (ISR) 
 
      This one-byte field occupies the 13th byte of a Type-4 record. If it contains "0" then the image 
      has been sampled at the preferred scanning rate of 19.68 pixels/mm (500 pixels per inch). If it 
      contains "1" then the image has been sampled at an alternative scanning rate as specified in the 
      Type-1 record. 
   */
   unsigned isr_;

   /*!
      4.1.6  Field 4.006: Horizontal Line Length (HLL)  
      This field is positioned at bytes 14 and 15 within the Type-4 record. It specifies the width of the 
      image by the number of pixels contained in each scan line. The first byte will be the most 
      significant.
   */
   unsigned hll_;

   /*!
      4.1.7  Field 4.007: Vertical Line Length (VLL)  
      This field records in bytes 16 and 17 the length of the image by the number of scan lines present 
      in the image. The first byte is the most significant. 
   */
   unsigned vll_;
   /*!
      4.1.8  Field 4.008: Gray-scale Compression Algorithm (GCA) 
 
      This one-byte field specifies the gray-scale compression algorithm used to encode the image 
      data. A binary zero indicates that no compression algorithm has been used. In this case pixels are 
      recorded in left to right, top to bottom fashion. The FBI will maintain a registry relating non-zero 
      numbers to compression algorithms. The INT-I will use the same allocation of numbers.
   */
   unsigned char cga_;
};

///! Запись Type-7 - Пользовательские изображения
class type7Record : public type4Record
{   
public:
   type7Record();
   ~type7Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   int write(FILE* out, unsigned len = 0);
protected:
   /*
   The sixth byte contains a one-byte identifier which specifies whether the image is of Category-1 
   (palm, finger-tips, sole and toe data) or Category-2 (other) data. The permissible values of this 
   field are: 
 
   1 Category-1 
   2 Category-2 
   */
   unsigned char imt_;                                              
   /*
   This one-byte field occupies the seventh byte position of a Type-7 record. The field contains a 
   code selected from the following table. 
 
   Table 7.1   - Image Description 
   */
   unsigned char imd_;
   /*
   When the Type-7 record is used for Category-1 image data, this field, of length ten bytes, 
   contains the pattern classification of the image, in any agreed format. If no classification is to be 
   included in the record, then these ten bytes contain binary zeros. 
 
   When the Type-7 record is used for Category-2 image data, these ten bytes contain zeros.   
   */
   unsigned char pcn_[10];
   /*
   This field of length eleven bytes consists of three subfields, starting at byte number 18. 
 
   When the Type-7 record is used for Category-1 image data, this field contains binary zeros. 
 
   When the Type-7 record is used for Category-2 image data, the three subfields consist of: 
 
   1  The scanning resolution of the captured image in pixels per 100mm (2 bytes) 
   2  The number of bytes which represent each pixel, up to a maximum of four (1 byte) 
   3  The value defining white pixels and the value defining black pixels (4 bytes each, most 
   significant first, unused bytes filled with zeros) 
 
   Scanning resolution is specified in units of pixels per 100mm using two bytes, the first being the 
   most significant. For example 7,176 represents (256*7)+176 = 1968, equivalent to 19.68 pixels 
   per mm (500 pixels per inch).
   */
   unsigned char imr_[11];
};

///! Запись Type-8 - Подписи
class type8Record : public type4Record
{   
public:
   type8Record();
   ~type8Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   int write(FILE* out, unsigned len = 0);
protected:
   /*The sixth byte contains the signature type field. The permissible values of this field are:  
   0  The signature is that of the fingerprinted subject 
   1  The signature is that of the fingerprinting officer.*/
   unsigned char sig_;
   /*
   This field indicates how the signature is stored, and is located at the seventh byte of the record. 
   The permissible values of this field are:  
   0  The image is uncompressed 
   1  The image is compressed 
   2  The image is vector data. 
   */
   unsigned char srt_;
};


///! Запись Type-9 - Мелкие особенности. Пока просто читаем как текстовую запись
class type9Record : public nistRecord
{   
public:
   type9Record();
   virtual ~type9Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
};


///! Запись Type-10 - Фото
class type10Record : public type4Record
{   
public:
   type10Record();
   ~type10Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   const std::string& getCGA(){return cga_;}
   const std::string& getIMT(){return imt_;}
   const std::string& getPHD(){return photo_date_;}
   const std::string& getPOS(){return pos_;}
   const std::string& getCSP(){return csp_;}
   unsigned getVPS(){return vps_;}
   unsigned getHPS(){return hps_;}
   unsigned char getSLC(){return slc_;}
protected:
   /*
   10.1.3  Field 10.003: Image Type (IMT)  
   This mandatory ASCII field is used to indicate the type of image contained in this record. It shall 
   contain "FACE", "SCAR", "MARK", or "TATTOO" to indicate a face, scar, mark or tattoo image.
   */
   std::string imt_;
   /*10.1.4  Field 10.004: Source Agency / ORI (SRC)*/
   std::string ori_;
   /*10.1.5  Field 10.005: Photo Date (PHD)*/
   std::string photo_date_;
   /*10.1.6  Field 10.006: Horizontal Line Length (HLL)*/
   /*10.1.7  Field 10.007: Vertical Line Length (VLL)*/
   /*10.1.8  Field 10.008: Scale Units (SLC)
   This mandatory ASCII field shall specify the units used to describe the image sampling 
   frequency (pixel density). A "1" in this field indicates pixels per inch, or a "2" indicates pixels 
   per centimeter. A "0" in this field indicates no scale is given. For this case, the quotient of 
   HPS/VPS gives the pixel aspect ratio. 
   */
   unsigned char slc_;
   /*10.1.9  Field 10.009: Horizontal Pixel Scale (HPS)
   This mandatory ASCII field shall specify the pixel density used in the horizontal direction 
   providing the SLC contains a "1" or a "2". Otherwise, it indicates the horizontal component of 
   the pixel aspect ratio.  
   */
   unsigned hps_;
   /*10.1.10  Field 10.010: Vertical Pixel Scale (VPS)
   This mandatory ASCII field shall specify the pixel density used in the vertical direction 
   providing the SLC contains a "1" or a "2". Otherwise, it indicates the vertical component of the 
   pixel aspect ratio. 
   */
   unsigned vps_;
   /*10.1.11  Field 10.011: Compression Algorithm (CGA)
   This mandatory ASCII field shall specify the algorithm used to compress the color or grayscale 
   image. An entry of "NONE" in this field indicates that the data contained in this record is
   uncompressed. For those images that are to be compressed, the preferred method for the 
   compression of facial and SMT images is specified by the baseline mode of the JPEG algorithm. 
   The data shall be formatted in accordance with the JPEG File Interchange Format, Version 1.02 
   (JFIF). An entry of "JPEGB" indicates that the scanned or captured image was compressed using 
   baseline JPEG. An entry of "JPEGL" indicates that the lossless mode of the JPEG algorithm was 
   used to compress the image. If the image is captured in grayscale, then only the luminescence 
   component will be compressed and transmitted. 
   */
   std::string cga_;
   /*
   10.1.12  Field 10.012: Colorspace (CSP)  
   This mandatory ASCII field shall contain the  color space used to exchange the image. For 
   compressed images, the preferred colorspace using baseline JPEG and JFIF is YCbCr to be 
   coded as "YCC". An entry of "GRAY" shall be used for all grayscale images. This field shall 
   contain "RGB" for uncompressed color images containing non-interleaved red, green, and blue 
   pixels in that order. All other colorspaces are undefined. 
   */
   std::string csp_;
   /*
   10.1.14  Field 10.020: Subject Pose (POS)
   This optional field is to be used for the exchange of facial image data. When included, this field 
   shall contain a one ASCII character code selected from Table 10.2 to describe the pose of the 
   subject. For the angled pose entry "A", field 10.021 shall contain the offset angle from the full 
   face orientation. 

   Full Face Frontal  F 
   Right Profile (90 degree)  R 
   Left Profile (90 degree)  L 
   Angled Pose  A 

   */
   std::string pos_;
   /*
   10.1.15  Field 10.021: Pose Offset Angle (POA) 
 
   This field shall only be used for the exchange of facial image data if Field 10.020 (POS) contains 
   an "A" to indicate an angled pose of the subject. This field should be omitted for a full face or a 
   profile. This ASCII field specifies the pose position of the subject at any possible orientation 
   within a circle. Its value shall be to a nearest degree. 
   */
   std::string poa_;
   /*
   10.1.16  Field 10.022: Photo Description (PXS) 
 
   This optional ASCII field shall be used for the exchange of facial image data. When present, it 
   shall describe special attributes of the captured facial image. Attributes associated with the facial 
   image may be selected from Table 10.3 and entered in this field. 
   */
   std::string pxs_;
};


///! Запись Type-13 - Следы
class type13Record : public type4Record
{   
public:
   type13Record();
   ~type13Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   const char* getCGA(){return cga_.c_str();}
   unsigned char getFGP();
   const std::string& getLCD(){return lcd_;}
   unsigned char getSLC(){return slc_;}
   unsigned getISR(){return vps_;}
   unsigned getVPS(){return vps_;}
   unsigned getHPS(){return hps_;}
   unsigned getBPX(){return bpx_;}
   const char* getCOM(){return com_.c_str();}
protected:
   /*
      11.1.3  Field 13.003: Impression type (IMP)  
      This mandatory one- or two-byte ASCII field shall indicate the manner by which the latent 
      image information was obtained.  The appropriate latent code choice selected from Table 4.1 
      (finger) or Table 13.2 (palm) shall be entered in this field. 
   */

   /*
      11.1.4  Field 13.004: Source agency / ORI (SRC) 
 
      This mandatory ASCII field shall contain the identification of the administration or organization 
      that originally captured the facial image contained in the record. Normally, the Originating 
      Agency Identifier (ORI) of the agency that captured the image will be contained in this field. It 
      consists of two information items in the following format 
 
       CC/agency. 
   */

   std::string ori_;
   /*
   11.1.5  Field 13.005: Latent capture date (LCD) 
 
   This mandatory ASCII field shall contain the date  that the latent image contained in the record 
   was captured. The date shall appear as eight digits in the format CCYYMMDD.  The CCYY 
   characters shall represent the year the image was captured; the MM characters shall be the tens 
   and units values of the month; and the DD characters shall be the tens and units values of the day 
   in the month.  For example, 20000229 represents February 29, 2000.  The complete date must be 
   a legitimate date. 
   */
   std::string lcd_;

   /*Field 13.006: Horizontal line length (HLL)*/
   /*Field 13.007: Vertical line length (VLL)*/

   /*
   Field 13.008: Scale units (SLC)  
   This mandatory ASCII field shall specify the units used to describe the image sampling 
   frequency (pixel density).  A "1" in this field indicates pixels per inch, or a "2" indicates pixels 
   per centimeter. A "0" in this field indicates no scale is given.  For this case, the quotient of 
   HPS/VPS gives the pixel aspect ratio. 
   */
   unsigned char slc_;

   /*
   Field 13.009: Horizontal pixel scale (HPS)  
   This mandatory ASCII field shall specify the  integer pixel density used in the horizontal 
   direction providing the SLC contains a "1" or a  "2".  Other-wise, it indicates the horizontal 
   component of the pixel aspect ratio. 
   */
   unsigned hps_;

   /*
   Field 13.010: Vertical pixel scale (VPS) 
   This mandatory ASCII field shall specify the integer pixel density used in the vertical direction 
   pro-viding the SLC contains a "1" or a "2".  Otherwise, it indicates the vertical component of the 
   pixel aspect ratio. 
   */
   unsigned vps_;

   /*
   Field 13.011: Compression algorithm (CGA) 
 
   This mandatory ASCII field shall specify the algorithm used to compress grayscale images.  An 
   entry of "NONE" in this field indicates that the data contained in this record is uncompressed. 
   For those images that are to be losslessly compressed, this field shall contain the preferred 
   method for the compression of latent fingerprint images. Valid compression codes are defined in 
   Table A7.1.
   */
   std::string cga_;

   /*
   11.1.12  Field 13.012: Bits per pixel (BPX) 
 
   This mandatory ASCII field shall contain the number of bits used to represent a pixel.  This field 
   shall contain an entry of ì8î for normal grayscale values of ì0î to ì255î.  Any entry in this field 
   greater than ì8î shall represent a grayscale pixel with increased precision. 
   */
   unsigned char bpx_;

   /*
      Field 13.013: Finger / palm position (FGP) 
      This mandatory tagged-field shall contain one or more the possible finger or palm positions that 
      may match the latent image.  The decimal code number corresponding to the known or most 
      probable finger position shall be taken from Table 4.2 or the most probable palm position from 
      Table 13.3 and entered as a one- or two-character ASCII subfield.  Additional finger and/or palm 
      positions may be referenced by entering the alternate position codes as subfields separated by the 
      ìRSî separator character.  The code "0", for "Unknown Finger", shall be used to reference every 
      finger position from one through ten.  The code ì20î, for 
 
      ìUnknown Palmî,  shall be used to reference every listed palmprint position. 

   */
   std::string fgp_;

   /*Field 13.014-019: Reserved for future definition (RSV) */

   /*
   Field 13.020: Comment (COM)  
   This optional field may be used to insert comments or other ASCII text information with the 
   latent image data. 
   */
   std::string com_;

   /*
   Fields 13.200-998: User-defined fields (UDF) 
 
   These fields are user-definable fields.  Their size and content shall be defined by the user and be 
   in accordance with the receiving agency.  If  present they shall contain ASCII textual 
   information. 
   */

};

///! Запись Type-14 - Пальцы
class type14Record : public type4Record
{   
public:
   type14Record();
   ~type14Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   const char* getCGA(){return cga_.c_str();}
   unsigned char getSLC(){return slc_;}
   unsigned getISR(){return vps_;}
   unsigned getVPS(){return vps_;}
   unsigned getHPS(){return hps_;}
   unsigned char getFGP() {return fgp_;}
protected:
   /*
   Field 14.003: Impression type (IMP)  
   This mandatory one-byte ASCII field shall indicate the manner by which the tenprint image 
   information was obtained.  The appropriate code selected from Table 4.1 shall be entered in this 
   field. 
   */

   /*Field 14.004: Source agency/ORI (SRC) */
   std::string ori_;
   /*Field 14.005: Tenprint capture date (TCD)*/
   std::string tcd_;

   /*Field 14.006: Horizontal line length (HLL)*/
   /*Field 14.007: Vertical line length (VLL)*/

   /*
   Field 14.008: Scale units (SLC)  
   This mandatory ASCII field shall specify the units used to describe the image sampling 
   frequency (pixel density).  A "1" in this field indicates pixels per inch, or a "2" indicates pixels 
   per centimeter. A "0" in this field indicates no scale is given.  For this case, the quotient of 
   HPS/VPS gives the pixel aspect ratio. 
   */
   unsigned char slc_;

   /*
   Field 14.008: Horizontal pixel scale (HPS)  
   This mandatory ASCII field shall specify the  integer pixel density used in the horizontal 
   direction providing the SLC contains a "1" or a  "2".  Other-wise, it indicates the horizontal 
   component of the pixel aspect ratio. 
   */
   unsigned hps_;

   /*
   Field 14.010: Vertical pixel scale (VPS) 
   This mandatory ASCII field shall specify the integer pixel density used in the vertical direction 
   providing the SLC contains a "1" or a "2".  Otherwise, it indicates the vertical component of the 
   pixel aspect ratio.  
   */
   unsigned vps_;

   /*
   Field 14.011: Compression algorithm (CGA) 
 
   This mandatory ASCII field shall specify the algorithm used to compress grayscale images.  An 
   entry of "NONE" in this field indicates that the data contained in this record is uncompressed. 
   For those images that are to be compressed, this field shall contain  the preferred method for the 
   compression of tenprint fingerprint images. Valid compression codes are defined in Table A7.1. 
   WSQ - 
   Algorithm to be used for the compression of grayscale images 
   in Type-4, Type-7 and Type-13 to Type-15 records. Shall not 
   be used for resolutions >500dpi. 

   J2K 
   To be used for lossy and losslessly compression of grayscale 
   images in Type-13 to Type-15 records. Strongly recommended 
   for resolutions >500 dpi 
   */
   std::string cga_;

   /*
   Field 14.012: Bits per pixel (BPX) 
 
   This mandatory ASCII field shall contain the number of bits used to represent a pixel.  This field 
   shall contain an entry of "8" for normal grayscale values of "0" to "255".  Any entry in this field 
   greater than or less than "8" shall represent  a grayscale pixel with increased or decreased 
   precision respectively.
   */
   unsigned char pbx_;

   /*
   Field 14.013: Finger position (FGP) 
 
   This mandatory tagged-field shall contain finger position that matches the tenprint image.  The 
   decimal code number corresponding to the known or most probable finger position shall be 
   taken from Table 4.2 and entered as a one- or two-character ASCII subfield.  Table 4.2 also lists 
   the maximum image area that can be transmitted for each of the fourteen possible finger 
   positions. Additional finger positions may be referenced in the transaction by entering the 
   alternate finger positions as subfields separated by the ìRSî separator character.  The code "0", 
   for "Unknown Finger", shall be used to reference every finger position from one through ten. 
   */
   unsigned char fgp_;

   /*
   Field 14.020: Comment (COM) 
 
   This optional field may be used to insert comments or other ASCII text information with the 
   palmprint image data.
   */
   std::string com_;
};

///! Запись Type-15 - Ладони
class type15Record : public type4Record
{   
public:
   type15Record();
   ~type15Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
   int write(FILE* out, unsigned len = 0);
   const char* getCGA(){return cga_.c_str();}
   unsigned char getPLP(){return plp_;}
   unsigned char getFGP(){return getPLP();}
   unsigned char getSLC(){return slc_;}
   unsigned getISR(){return vps_;}
   unsigned getVPS(){return vps_;}
   unsigned getHPS(){return hps_;}
protected:
   /*
   13.1.3  Field 15.003: Impression type (IMP) 
      Live-scan palm          10 
      Nonlive-scan palm       11 
      Latent palm impression  12 
      Latent palm tracing     13 
      Latent palm photo       14 
      Latent palm lift        15 
   */

   /*Field 15.004: Source agency/ORI (SRC) */
   std::string ori_;
   /*Field 15.005: Palmprint capture date (PCD)*/
   std::string pcd_;

   /*Field 15.006: Horizontal line length (HLL)*/
   /*Field 15.007: Vertical line length (VLL)*/

   /*
   Field 15.008: Scale units (SLC)  
   This mandatory ASCII field shall specify the units used to describe the image sampling 
   frequency (pixel density).  A "1" in this field indicates pixels per inch, or a "2" indicates pixels 
   per centimeter. A "0" in this field indicates no scale is given.  For this case, the quotient of 
   HPS/VPS gives the pixel aspect ratio. 
   */
   unsigned char slc_;
   /*
   Field 15.009: Horizontal pixel scale (HPS)  
   This mandatory ASCII field shall specify the  integer pixel density used in the horizontal 
   direction providing the SLC contains a "1" or a  "2".  Other-wise, it indicates the horizontal 
   component of the pixel aspect ratio. 
   */
   unsigned hps_;

   /*
   Field 15.010: Vertical pixel scale (VPS) 
   This mandatory ASCII field shall specify the integer pixel density used in the vertical direction 
   providing the SLC contains a "1" or a "2".  Otherwise, it indicates the vertical component of the 
   pixel aspect ratio.  
   */
   unsigned vps_;

   /*
   Field 15.011: Compression algorithm (CGA) 
 
   This mandatory ASCII field shall specify the algorithm used to compress grayscale images.  An 
   entry of "NONE" in this field indicates that the data contained in this record is uncompressed. 
   For those images that are to be compressed, this field shall contain  the preferred method for the 
   compression of tenprint fingerprint images. Valid compression codes are defined in Table A7.1. 
   WSQ - 
   Algorithm to be used for the compression of grayscale images 
   in Type-4, Type-7 and Type-13 to Type-15 records. Shall not 
   be used for resolutions >500dpi. 

   J2K 
   To be used for lossy and losslessly compression of grayscale 
   images in Type-13 to Type-15 records. Strongly recommended 
   for resolutions >500 dpi 
   */
   std::string cga_;

   /*
   Field 15.012: Bits per pixel (BPX) 
 
   This mandatory ASCII field shall contain the number of bits used to represent a pixel.  This field 
   shall contain an entry of "8" for normal grayscale values of "0" to "255".  Any entry in this field 
   greater than or less than "8" shall represent  a grayscale pixel with increased or decreased 
   precision respectively.
   */
   unsigned char pbx_;

   /*
   Field 15.013: Palmprint position (PLP) 
 
   This mandatory tagged-field shall contain the  palmprint position that matches the palmprint 
   image.  The decimal code number corresponding to the known or most probable palmprint 
   position shall be taken from Table 13.3 and entered as a two-character ASCII subfield.  Table 
   13.3 also lists the maximum image areas and dimensions  for each of the possible palmprint 
   positions. 
   
   Palm Position  Palm code Image Width   Height 
                            area   (mm)   (mm) 
                            (mm2) 
   Unknown Palm         20  28387  139.7  203.2 
   Right Full Palm      21  28387  139.7  203.2 
   Right Writer s Palm  22  5645    44.5  127.0 
   Left Full Palm       23  28387  139.7  203.2 
   Left Writer s Palm   24  5645    44.5  127.0 
   Right Lower Palm     25  19516  139.7  139.7 
   Right Upper Palm     26  19516  139.7  139.7 
   Left Lower Palm      27  19516  139.7  139.7 
   Left Upper Palm      28  19516  139.7  139.7 
   Right Other          29  28387  139.7  203.2 
   Left Other           30  28387  139.7  203.2


   */
   unsigned char plp_;

   /*
   Field 15.020: Comment (COM) 
 
   This optional field may be used to insert comments or other ASCII text information with the 
   palmprint image data.
   */
   std::string com_;
};

///! Запись Type-99 - CBEFF. Пока просто читаем как текстовую запись
class type99Record : public nistRecord
{   
public:
   type99Record();
   virtual ~type99Record();
   bool load(const std::vector<unsigned char>&, unsigned& offset);
};

///! Класс парсера ANSI-NIST файлов
class nistParser
{
public:
   nistParser();
   ~nistParser();
   /// Reads file in to internal buffer, then call load from this buffer
   bool load(const std::string&,bool force=false);
   /// Loads ANSI-NIS file data from memory buffer. Buffer should be valid until obect destruction.
   bool load(const std::vector<unsigned char>&,bool force=false);
   bool write(std::vector<nistRecord*> records_);
   /// Service function for reading file in to memory
   static bool readFile(const std::string& file_name,std::vector<unsigned char>& content);
   bool writeFile(const std::string& output_file_name);
   /// Unit Separator  Separates information items 
   static unsigned char US() {return 0x1F;}
   /// Record Separator  Separates subfields
   static unsigned char RS() {return 0x1E;}
   /// Group Separator  Separates fields
   static unsigned char GS() {return 0x1D;}
   /// File Separator  Separates logical records 
   static unsigned char FS() {return 0x1C;}
   std::string getTOT();
   std::string getORI();
   std::string getDAI();
   std::string getTCN();
   std::string getTCR();
   std::string getDOM();
   double getISR();
   type1Record* getFileHeader(){return &header_;}
   std::vector<nistRecord*> getRecords(unsigned type);
protected:
   std::string err_msg_;
   std::vector<unsigned char> file_data_;
   type1Record header_;
   std::vector<nistRecord*> records_;
};



#endif // NIST_PARSER_H
