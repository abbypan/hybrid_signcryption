
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1])
 
df_hs = df %>% group_by(type, msg_len) %>% summarise(
                                                         avg_all_len=mean(all_len), 
                                                         avg_delta_len=mean(all_len-msg_len), 
                                                         #avg_all_len1=mean(all_len/1024), 
                                                         #avg_all_len2=mean(all_len/1024/1024), 
                                                         avg_enc_time=mean(enc_elapsed_time_sd*1000), 
                                                         avg_dec_time=mean(dec_elapsed_time_sd*1000), 
                                                         #median_all_len=median(all_len), 
                                                         #median_enc_time=median(enc_elapsed_time_sd), 
                                                         #median_dec_time=median(dec_elapsed_time_sd), 
                                                         .groups = 'drop')
df_hs %>% write.csv(args[2] , row.names = F)

