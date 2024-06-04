% Set 0 0 to top-center of page
centerX marginY1 16 sub translate

% Header/data format
/Helvetica-Bold findfont 16 scalefont setfont
0 0 moveto (Data Format) centreshow

0 -24 translate
drawDataFormat

% bech32->binary chart
0 -100 translate
/Helvetica-Bold findfont 16 scalefont setfont
0 0 moveto  (Bech32 to Binary Conversion) centreshow

0 -24 translate
false drawBech32BinaryTable

0 -150 translate
/Helvetica-Bold findfont 16 scalefont setfont
0 0 moveto (Binary to Bech32 Conversion) centreshow

0 -24 translate
true drawBech32BinaryTable

% Symbol pronunciation
0 -150 translate
/Helvetica-Bold findfont 16 scalefont setfont
0 0 moveto (Symbols) centreshow

0 -24 translate
drawSymbolTable
