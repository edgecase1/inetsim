// sample_gui.c - default GUI binary for INetSim
//
// (c)2007,2008 Matthias Eckert, Thomas Hungenberg
//
// Compile with: cl /nologo sample_gui.c user32.lib

#include <windows.h>



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    MessageBox (NULL, "This is the INetSim default binary" , "INetSim", 0);
    return 0;
} 
