void recrusive(char *p_flag,int *p_globar_var_54,int counter_0)

{
    int *p_gloval_var_54_copy;
    char *p_flag_copy;
    
    counter_0 = counter_0 + *p_flag;
    if (*p_globar_var_54 < 0) {
        printf("Well done: your flag is indeed CCIT{%s}\n",FLAG);
                                        /* WARNING: Subroutine does not return */
        exit(0);
    }
    p_gloval_var_54_copy = p_globar_var_54;
    p_flag_copy = p_flag;
    if (counter_0 == *p_globar_var_54) {
        p_gloval_var_54_copy = p_globar_var_54 + 1;
        p_flag_copy = p_flag + 1;
        recrusive(p_flag_copy,p_gloval_var_54_copy,counter_0);
    }
    recrusive(p_flag_copy,p_gloval_var_54_copy,counter_0 - *p_flag_copy);
    return;
}