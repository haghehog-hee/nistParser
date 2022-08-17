/**  \file  pack_ret.h
     \author Nicolay V. Moskvichev
     \date   13.05.2004

    \brief   Вернуть выравнивание данных к предыдущему состоянию.

    Выталкивает из стека препроцессора установки выравнивания.
    \b Должен использоваться для отмены выравнивания, установленного файлами
    \ref pack_set1.h, \ref pack_set2.h, \ref pack_set4.h, \ref pack_set8.h
    \par
    Компиляторы: Borland, Microsoft, gcc, xlC.
*/
#if defined(_MSC_VER) || defined(__BORLANDC__) || defined (__IBMCPP__) || defined(__GNUC__)
#pragma pack(pop)
#endif
