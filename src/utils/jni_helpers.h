/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _DY_JNI_HELPERS_INCLUDE_
#define _DY_JNI_HELPERS_INCLUDE_

#include "ub_convert.h"

namespace ub {

  static std::string jni_string_get(JNIEnv * env, jstring javaString)
  {
    if (!javaString) return "";
    const_char_ptr chars = env->GetStringUTFChars(javaString, 0);
    std::string s = chars ? chars : "";
    env->ReleaseStringUTFChars(javaString, chars);
    return s;
  }

  static std::string jni_string_get(JNIEnv * env, jcharArray javaChars)
  {
    if (!javaChars) return "";
    int len = env->GetArrayLength(javaChars);

    std::string out;
    void* temp = env->GetPrimitiveArrayCritical(javaChars, nullptr);
    if (temp) 
    {
      out = ub::utf16le.convert(mem_t(const_byte_ptr(temp), len*2));
      env->ReleasePrimitiveArrayCritical(javaChars, temp, JNI_ABORT);
    }

    return out;
  }

  static void jni_set_integer(JNIEnv * env, jobject object, int value)
  {
    jclass clazz = env->GetObjectClass(object);
    jfieldID field_id = env->GetFieldID(clazz, "value", "I");
    env->SetIntField(object, field_id, value);
  }

  static int jni_get_integer(JNIEnv * env, jobject object)
  {
    jclass clazz = env->GetObjectClass(object);
    jfieldID field_id = env->GetFieldID(clazz, "value", "I");
    return env->GetIntField(object, field_id);
  }

  static void jni_set_byte(JNIEnv * env, jobject object, jbyte value)
  {
    jclass clazz = env->GetObjectClass(object);
    jfieldID field_id = env->GetFieldID(clazz, "value", "B");
    env->SetByteField(object, field_id, value);
  }

  static jbyte jni_get_byte(JNIEnv * env, jobject object)
  {
    jclass clazz = env->GetObjectClass(object);
    jfieldID field_id = env->GetFieldID(clazz, "value", "B");
    return env->GetByteField(object, field_id);
  }

  static std::string from_j_string(JNIEnv * env, jstring j_string)
  {
    const_char_ptr ptr = j_string ? env->GetStringUTFChars(j_string, nullptr) : "";
    std::string s = ptr;
    if (j_string) env->ReleaseStringUTFChars(j_string, ptr);
    return s;
  }

  class jni_buf_t : public mem_t
  {
  public:
    ~jni_buf_t()
    {
      if (data) 
      {
        ub::secure_bzero(data, buf_size);
        delete[] data;
      }
    }

  protected:  
    jni_buf_t(JNIEnv * env, jbyteArray jarray, int offset = 0, int size = -1)
    {
      this->data = nullptr;
      this->env = nullptr;
      this->jarray = nullptr;
      this->size = 0;
      this->length = 0;
      this->buf_size = 0;

      if (offset < 0) offset = 0;

      if (!env || !jarray) return;
      length = env->GetArrayLength(jarray);
      if (offset >= length) return;

      if (size < 0) size = length;
      if (offset + size > length) size = length - offset;
      if (size <= 0) return;

      this->offset = offset;
      this->env = env;
      this->jarray = jarray;
      this->buf_size = this->size = size;
      this->data = new byte_t[size];
      //memset(this->data, 0xa5, size);
    }

    void load()
    {
      if (size>0) env->GetByteArrayRegion(jarray, offset, size, (jbyte*)data);
    }

    void save(int size=-1) 
    {
      if (!env || !jarray) return;
      if (offset >= length) return;
      if (size < 0) size = this->size;
      if (offset + size > length) size = length - offset;
      if (size > buf_size) size = buf_size;
      if (size > 0) env->SetByteArrayRegion(jarray, offset, size, (jbyte*)data);
    }

  protected:
    JNIEnv * env;
    jbyteArray jarray;
    int length, offset, buf_size;
  };

  class jni_in_buf_t : public jni_buf_t
  {
  public:   
    jni_in_buf_t(JNIEnv * env, jbyteArray jarray, int offset = 0, int size = -1) : jni_buf_t(env, jarray, offset, size) { load(); }
  };

  class jni_inout_buf_t : public jni_buf_t
  {
  public:   
    jni_inout_buf_t(JNIEnv * env, jbyteArray jarray, int offset = 0, int size = -1) : jni_buf_t(env, jarray, offset, size) { load(); }
    void save(int size=-1) { jni_buf_t::save(size); }
  };

  class jni_out_buf_t : public jni_buf_t
  {
  public:   
    jni_out_buf_t(JNIEnv * env, jbyteArray jarray, int offset = 0, int size = -1) : jni_buf_t(env, jarray, offset, size) {}
    void save(int size=-1) { jni_buf_t::save(size); }
  };


  class jni_critical_buf_t : public mem_t
  {
  public:
    jni_critical_buf_t(JNIEnv * _env, jbyteArray _array, int offset = 0, int _size = -1) : env(_env), array(_array), jdata(nullptr)
    {
      data = nullptr;
      size = 0;
      if (!array) return; 
      jdata = env->GetPrimitiveArrayCritical(array, nullptr);
      if (!jdata) return; 
      if (_size < 0) size = env->GetArrayLength(array);
      else size = _size;
      data = byte_ptr(jdata) + offset;
    }

    ~jni_critical_buf_t()
    {
      if (array && data) env->ReleasePrimitiveArrayCritical(array, jdata, JNI_ABORT);
    }

    void save()
    {
      if (array && data) env->ReleasePrimitiveArrayCritical(array, jdata, 0);
      array = nullptr;
      data = nullptr;
    }

  private:
    void* jdata;
    JNIEnv * env;
    jbyteArray array;
  };

  
  class java_field_t
  {
  protected:
    java_field_t(const_char_ptr _type, const_char_ptr _name)  :
      initialized(ub::once_init), field_id(nullptr),
      type(_type),
      name(_name) 
    {
    }

  protected:
    ub::once_t initialized;
    jfieldID field_id;
    const char* name;
    const char* type;

    void init(JNIEnv* env, jobject object)
    {
      if (!ub::once_begin(initialized)) return;
      jclass clazz = env->GetObjectClass(object);
      field_id = env->GetFieldID(clazz, name, type);
      ub::once_end(initialized);
    }
  };

  class java_bool_field_t : public java_field_t
  {
  public:
    java_bool_field_t(const_char_ptr name) : java_field_t("Z", name) {}
    bool get(JNIEnv* env, jobject object) { init(env, object); return env->GetBooleanField(object, field_id)!=0; }
    void set(JNIEnv* env, jobject object, bool value) { init(env, object); env->SetBooleanField(object, field_id, value ? 1 : 0); }
  };

  class java_byte_field_t : public java_field_t
  {
  public:
    java_byte_field_t(const_char_ptr name) : java_field_t("B", name) {}
    uint8_t get(JNIEnv* env, jobject object) { init(env, object); return env->GetByteField(object, field_id); }
    void set(JNIEnv* env, jobject object, uint8_t value) { init(env, object); env->SetByteField(object, field_id, value); }
  };

  class java_int_field_t : public java_field_t
  {
  public:
    java_int_field_t(const_char_ptr name) : java_field_t("I", name) {}
    uint32_t get(JNIEnv* env, jobject object) { init(env, object); return env->GetIntField(object, field_id); }
    void set(JNIEnv* env, jobject object, uint32_t value) { init(env, object); env->SetIntField(object, field_id, value); }
  };

  class java_long_field_t : public java_field_t
  {
  public:
    java_long_field_t(const_char_ptr name) : java_field_t("J", name) {}
    uint64_t get(JNIEnv* env, jobject object) { init(env, object); return env->GetLongField(object, field_id); }
    void set(JNIEnv* env, jobject object, uint64_t value)  { init(env, object); env->SetLongField(object, field_id, value); }
  };

  class java_object_field_t : public java_field_t
  {
  public:
    java_object_field_t(const_char_ptr type, const_char_ptr name) : java_field_t(type, name) {}
    jobject get(JNIEnv* env, jobject object) { init(env, object); return env->GetObjectField(object, field_id); }
    void set(JNIEnv* env, jobject object, jobject value) { init(env, object); env->SetObjectField(object, field_id, value); }
  };

  class java_array_field_t : public java_object_field_t
  {
  public:
    java_array_field_t(const_char_ptr type, const_char_ptr name) : java_object_field_t(type, name) {}
    jarray get(JNIEnv* env, jobject object) { init(env, object); return (jarray)env->GetObjectField(object, field_id); }
    void set(JNIEnv* env, jobject object, jarray value) { init(env, object); env->SetObjectField(object, field_id, value); }
  };

  class java_chars_field_t : public java_object_field_t
  {
  public:
    java_chars_field_t(const_char_ptr name) : java_object_field_t("[C", name) {}
    void set(JNIEnv* env, jobject object, const std::string& value)
    {
      int length = (int)value.length();
      jcharArray a = env->NewCharArray(length);

      jchar* temp = env->GetCharArrayElements(a, NULL);
      for (int i=0; i<length; i++) temp[i] = value[i];
      env->ReleaseCharArrayElements(a, temp, 0);

      java_object_field_t::set(env, object, a);
    }
    jcharArray get(JNIEnv* env, jobject object) { init(env, object); return (jcharArray)env->GetObjectField(object, field_id); }
  };

  class java_byte_array_field_t : public java_object_field_t
  {
  public:
    java_byte_array_field_t(const_char_ptr name) :  java_object_field_t("[B", name) {}
    jbyteArray get(JNIEnv* env, jobject object) { init(env, object); return (jbyteArray)env->GetObjectField(object, field_id); }
  };

}

#endif //_DY_JNI_HELPERS_INCLUDE_