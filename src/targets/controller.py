# -*- coding: utf-8 -*-
import datetime
import time
from functools import partial

from django.db import models
from django.db.models import Q

from agents.scans.models import ScansModel
from one_users.models import OneUsers
from one_users.serializers import OneUserSerializerEmail
from sadmin.plugins.models import PluginsModel
from targets.models import TasksModel, TaskStatisticsModel


def setTimeScheduler(scheduler):
    # if not scheduler.status:
    #     return
    # if scheduler.next_time <= scheduler.last_time:
    current_date = datetime.datetime.now().date()
    next_date = current_date + datetime.timedelta(days=scheduler.time_interval)
    next_datetime = datetime.datetime.combine(next_date,
                                              datetime.datetime.strptime(scheduler.started_at, "%H:%M").time())
    next_time = int(time.mktime(next_datetime.timetuple()))
    scheduler.next_time = next_time
    scheduler.save()


def setTimeSchedulerAfterScan(target):
    scheduler = target.configuration.scheduler
    if not scheduler.status:
        return
    if target.status >= 3:
        scheduler = target.configuration.scheduler
        last_time = target.last_scan
        scheduler.last_time = time.mktime(last_time.timetuple())
        scheduler.save()
        if scheduler.next_time <= scheduler.last_time:
            setTimeScheduler(scheduler)
            # next_day = scheduler.time_interval * 24 * 60 * 60
            # scheduler.next_time += next_day
            # scheduler.save()
            # else:
            #     print "test"
            # elif target.status < 3:
            # pass


def checkTargetAfterTasks(task_model):
    # print task_model.status
    target = task_model.target
    status = task_model.status
    if status >= 3:
        target.report_file = task_model.report_file
        target.last_scan = task_model.stop_time
    target.status = status
    target.save()
    setTimeSchedulerAfterScan(target=target)


def get_list_email():
    queryset = OneUsers.objects.filter(~Q(id=2), is_active=True)
    listemail = [str(use) for use in queryset]
    return listemail


def get_list_email_notify(list_email):
    listemail = []
    for email in list_email:
        try:
            user = OneUsers.objects.get(email=email, is_active=True)
            listemail.append(user)
        except:
            pass
    list_email = OneUserSerializerEmail(listemail, many=True).data
    if list_email is None:
        list_email = []
    return list_email


def create_tasks(target):
    task = TasksModel(target=target, name="%s - %s" % (target.name, str(int(time.time()))), target_addr=target.address)
    task.save()
    statistics = TaskStatisticsModel(task=task, time_scan=int(time.time()))
    statistics.save()
    if target.tasks_count is None:
        target.tasks_count = 1
    else:
        target.tasks_count += 1
    target.status = 0
    target.last_task_id = task.pk
    target.save()
    plugin_models = PluginsModel.objects.all()
    for plugin in plugin_models:
        new_scan = ScansModel(plugin=plugin, task=task)
        new_scan.save()
    return task


def checkTasksAfterScans(scan_model):
    task_model = scan_model.task
    # print "check scan: "
    # print scan_model.status
    if scan_model.status == 1:
        if task_model.status < 1:
            task_model.status = 1
            task_model.save()
    if scan_model.status == 2:
        if task_model.status < 2:
            task_model.status = 2
            task_model.start_time = int(time.time())
            task_model.save()
            statistics = task_model.task_statistics  # update time scan of statistic
            statistics.time_scan = int(time.time())
            statistics.save()
    elif scan_model.status == 5 or scan_model.status == 4 or scan_model.status == 3:
        scans_models = ScansModel.objects.filter(task=scan_model.task)
        is_finish = True
        is_error = False
        is_stop = False
        for scan_model in scans_models:
            if scan_model.status < 3:
                is_finish = False
                break
            if scan_model.status == 4:
                is_error = True
            if scan_model.status == 3:
                is_stop = True
        if is_finish:
            task_model.status = 5
            if is_error:
                task_model.status = 4
            if is_stop:
                task_model.status = 3
            task_model.finish_time = int(time.time())
            task_model.save()
            report = {"url": task_model.url, "details": [1, 2, 3]}
            list_tools = ["", "nmap", "metasploit", "nessus"]
            for scan_model in task_model.scans.all():
                report[list_tools[scan_model.tool.id]] = {"tool_id": scan_model.tool.id,
                                                          "scan": scan_model.id,
                                                          "start_time": scan_model.start_time,
                                                          "finish_time": scan_model.finish_time}
            task_model.save()
    checkTargetAfterTasks(task_model=task_model)


def get_model_attr(instance, attr):
    """Example usage: get_model_attr(instance, 'category__slug')"""
    for field in attr.split('__'):
        instance = getattr(instance, field)
    return instance


def next_or_prev_in_order(instance, qs=None, prev=False, loop=False):
    """Get the next (or previous with prev=True) item for instance, from the
       given queryset (which is assumed to contain instance) respecting
       queryset ordering. If loop is True, return the first/last item when the
       end/start is reached. """

    if not qs:
        qs = instance.__class__.objects.all()

    if prev:
        qs = qs.reverse()
        lookup = 'lt'
    else:
        lookup = 'gt'

    q_list = []
    prev_fields = []

    if qs.query.extra_order_by:
        ordering = qs.query.extra_order_by
    elif not qs.query.default_ordering:
        ordering = qs.query.order_by
    else:
        ordering = qs.query.order_by or qs.query.get_meta().ordering

    ordering = list(ordering)

    for field in (ordering + ['pk']):
        if field[0] == '-':
            this_lookup = (lookup == 'gt' and 'lt' or 'gt')
            field = field[1:]
        else:
            this_lookup = lookup
        q_kwargs = dict([(f, get_model_attr(instance, f))
                         for f in prev_fields])
        key = "%s__%s" % (field, this_lookup)
        q_kwargs[key] = get_model_attr(instance, field)
        q_list.append(models.Q(**q_kwargs))
        prev_fields.append(field)
    try:
        return qs.filter(reduce(models.Q.__or__, q_list))[0]
    except IndexError:
        length = qs.count()
        if loop and length > 1:
            # queryset is reversed above if prev
            return qs[0]
    return None


next_in_order = partial(next_or_prev_in_order, prev=False)
prev_in_order = partial(next_or_prev_in_order, prev=True)
