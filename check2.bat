@echo off
setlocal enabledelayedexpansion

rem Ruta de las tres carpetas que se deben comparar
set "folder1=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\json"
set "folder2=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\shn"
set "folder3=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\mc4"

rem Ruta de la carpeta donde se copiarán los archivos con el mismo nombre
set "output_folder=C:\Users\-kme-\Documents\GitHub\GoldHEN_Cheat_Repository\similares"

rem Iterar sobre los archivos en la primera carpeta
for %%F in ("%folder1%\*.*") do (
    rem Obtener el nombre del archivo sin extensión
    set "filename=%%~nF"

    rem Comprobar si el archivo con el mismo nombre existe en la segunda carpeta
    if exist "%folder2%\!filename!.*" (
        rem Copiar el archivo a la carpeta de salida
        copy "%%F" "%output_folder%\"
    )

    rem Comprobar si el archivo con el mismo nombre existe en la tercera carpeta
    if exist "%folder3%\!filename!.*" (
        rem Copiar el archivo a la carpeta de salida
        copy "%%F" "%output_folder%\"
    )
)

rem Iterar sobre los archivos en la segunda carpeta
for %%F in ("%folder2%\*.*") do (
    rem Obtener el nombre del archivo sin extensión
    set "filename=%%~nF"

    rem Comprobar si el archivo con el mismo nombre existe en la primera carpeta
    if exist "%folder1%\!filename!.*" (
        rem Copiar el archivo a la carpeta de salida
        copy "%%F" "%output_folder%\"
    )

    rem Comprobar si el archivo con el mismo nombre existe en la tercera carpeta
    if exist "%folder3%\!filename!.*" (
        rem Comprobar si el archivo ya ha sido copiado
        if not exist "%output_folder%\!filename!.*" (
            rem Copiar el archivo a la carpeta de salida
            copy "%%F" "%output_folder%\"
        )
    )
)

rem Iterar sobre los archivos en la tercera carpeta
for %%F in ("%folder3%\*.*") do (
    rem Obtener el nombre del archivo sin extensión
    set "filename=%%~nF"

    rem Comprobar si el archivo con el mismo nombre existe en la primera carpeta
    if exist "%folder1%\!filename!.*" (
        rem Copiar el archivo a la carpeta de salida
        copy "%%F" "%output_folder%\"
    )

    rem Comprobar si el archivo con el mismo nombre existe en la segunda carpeta
    if exist "%folder2%\!filename!.*" (
        rem Comprobar si el archivo ya ha sido copiado
        if not exist "%output_folder%\!filename!.*" (
            rem Copiar el archivo a la carpeta de salida
            copy "%%F" "%output_folder%\"
        )
    )
)

rem Mostrar un mensaje cuando se hayan copiado todos los archivos
echo Listo. Los archivos con el mismo nombre han sido copiados a %output_folder%.
