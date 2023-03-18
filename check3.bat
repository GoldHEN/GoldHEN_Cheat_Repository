@echo off
setlocal enabledelayedexpansion

rem Ruta de las tres carpetas que se deben comparar
set "folder1=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\json"
set "folder2=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\shn"
set "folder3=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\mc4"

rem Carpeta para la copia de respaldo
set "backup=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\similares"

rem Crear la carpeta de respaldo si no existe
if not exist "%backup%" mkdir "%backup%"

rem Iterar sobre los archivos en la primera carpeta
for %%F in ("%folder1%\*") do (
    rem Obtener el nombre del archivo sin extensión
    set "filename=%%~nF"

    rem Comprobar si el archivo con el mismo nombre existe en la segunda carpeta
    if exist "%folder2%\!filename!.*" (
        rem Hacer una copia de respaldo del archivo duplicado en la carpeta 2
        copy "%folder2%\!filename!.*" "%backup%"

        rem Eliminar el archivo duplicado en la carpeta 2
        del "%folder2%\!filename!.*"
    )

    rem Comprobar si el archivo con el mismo nombre existe en la tercera carpeta
    if exist "%folder3%\!filename!.*" (
        rem Hacer una copia de respaldo del archivo duplicado en la carpeta 3
        copy "%folder3%\!filename!.*" "%backup%"

        rem Eliminar el archivo duplicado en la carpeta 3
        del "%folder3%\!filename!.*"
    )
)

rem Iterar sobre los archivos en la segunda carpeta
for %%F in ("%folder2%\*") do (
    rem Obtener el nombre del archivo sin extensión
    set "filename=%%~nF"

    rem Comprobar si el archivo con el mismo nombre existe en la tercera carpeta
    if exist "%folder3%\!filename!.*" (
        rem Hacer una copia de respaldo del archivo duplicado en la carpeta 3
        copy "%folder3%\!filename!.*" "%backup%"

        rem Eliminar el archivo duplicado en la carpeta 3
        del "%folder3%\!filename!.*"
    )
)
