use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jint;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_packetsniffer_NativeBridge_runPacketLoop(
    _env: JNIEnv,
    _class: JClass,
    fd: jint,
) {
    std::thread::spawn(move || {
        // packet read/write loop goes here
    });
}
