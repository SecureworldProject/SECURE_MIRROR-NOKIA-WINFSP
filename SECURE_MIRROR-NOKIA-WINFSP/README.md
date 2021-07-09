# SECURE_MIRROR-NOKIA
modulo que crea un Virtual file system espejo de un file system real y ejecuta la logica definida en secureworld

## Instrucciones

Preparacion entorno: Es imprescindible que tengas el driver de dokan instalado.
El entorno esta preparado para la versión release en arquitecturas x64, basta con "build solution"

Ejecución del programa:
securemirror.exe /r "Ruta que queremos reflejar" /l "Letra o carpeta vacia sobre la que ejecutar dokan"

...


### Posibles errores
1. Errores de compilacion o de linkado: Estos errores se pueden dar si no tienes la carpeta Dokan_Files, con las cabeceras de las dlls necesarias y el fichero dokan1.lib necesario para el linkado
2. _CRT_SECURE_NO_WARNINGS : Este error ser puede ser resuelto en propiedades del proyecto (todas las configuraciones) --> C/C++ --> Preprocessor --> Preprocessor Definitions y aquí añadir _CRT_SECURE_NO_WARNINGS
