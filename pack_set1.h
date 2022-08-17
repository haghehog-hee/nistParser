/**  \file  pack_set1.h
     \author Nicolay V. Moskvichev
     \date   13.05.2004

    \brief   Установить выравнивание на 1 байт.

    Устанавливает выравнивание данных на 1 байт.
    Предыдущие установки заталкивает в стек препроцессора.
    Для возврата к предыдущему состоянию необходимо использовать \ref pack_ret.h
    \par
    Компиляторы: Borland, Microsoft, gcc, xlC.
*/

#if defined(_MSC_VER)
#pragma warning( disable : 4103 )
#endif

#if defined(__BORLANDC__)
#pragma warning(push)
#if (__BORLANDC__  > 0x0520)
#pragma warn -8059
#else
#pragma warn -pck
#endif
#endif

#if defined (__IBMCPP__)
#pragma pack(1)
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__GNUC__)
#pragma pack(push,1)
#define PACKED_1
#endif
