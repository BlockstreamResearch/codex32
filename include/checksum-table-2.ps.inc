10 dict begin
pgsize aload pop
/pageW exch def
/pageH exch def

0 pageH neg translate

/Helvetica-Bold findfont 10 scalefont setfont
pageW 2 div pageH 48 sub moveto (MS32 Checksum Table) centreshow

/Courier findfont 8.5 scalefont setfont
36 pageH 64 sub  % x y
pageW 64 sub pageH 144 sub 2 div % w h
16 drawChecksumTable

36 pageH 2 div 16 sub % x y
pageW 64 sub pageH 144 sub 2 div % w h
24 drawChecksumTable
end
