hdc shell mount -o rw,remount /
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_sdk.dylib.so ./system/lib64/
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_sdk_ffi.z.so ./system/lib64/
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_ndk.z.so ./system/lib64/ndk/
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_service.dylib.so ./system/lib64/
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_napi.z.so ./system/lib64/module/security
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\lib.unstripped\security\asset\libasset_service_ffi.z.so ./system/lib64/
hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\security\asset\hisysevent.def ./system/etc/hiview/

hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\exe.unstripped\tests\unittest\asset\asset_UT_test\asset_c_ndk_test ./data/

hdc shell chmod 777 ./data/asset_c_ndk_test

hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\exe.unstripped\tests\unittest\asset\asset_UT_test\asset_c_api_test ./data/

hdc shell chmod 777 ./data/asset_c_api_test

hdc file send \\7.222.59.152\z00639827\workspace\hmos_asset\out\generic_generic_arm_64only\hisi_higeneric_newphone_standard\exe.unstripped\tests\unittest\asset\asset_UT_test\asset_rust_test ./data/

hdc shell chmod 777 ./data/asset_rust_test

hdc shell reboot
pause